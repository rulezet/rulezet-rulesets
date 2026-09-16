rule TTP_XOR_QUAD_CurrentVersionRun_7e23 {
  strings:
    $key_7e23 = { 2d 4c [2] 09 42 [2] 22 6e [2] 0c 4c [2] 18 57 [2] 17 4d [2] 09 50 [2] 0b 51 [2] 10 57 [2] 0c 50 [2] 10 7f }

  condition:
    any of them
}