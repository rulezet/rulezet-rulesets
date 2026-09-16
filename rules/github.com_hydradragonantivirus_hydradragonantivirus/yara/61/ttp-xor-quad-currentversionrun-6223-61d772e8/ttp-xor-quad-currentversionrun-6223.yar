rule TTP_XOR_QUAD_CurrentVersionRun_6223 {
  strings:
    $key_6223 = { 31 4c [2] 15 42 [2] 3e 6e [2] 10 4c [2] 04 57 [2] 0b 4d [2] 15 50 [2] 17 51 [2] 0c 57 [2] 10 50 [2] 0c 7f }

  condition:
    any of them
}