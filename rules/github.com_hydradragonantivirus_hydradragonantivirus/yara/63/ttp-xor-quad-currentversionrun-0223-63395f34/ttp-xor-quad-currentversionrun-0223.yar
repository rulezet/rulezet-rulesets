rule TTP_XOR_QUAD_CurrentVersionRun_0223 {
  strings:
    $key_0223 = { 51 4c [2] 75 42 [2] 5e 6e [2] 70 4c [2] 64 57 [2] 6b 4d [2] 75 50 [2] 77 51 [2] 6c 57 [2] 70 50 [2] 6c 7f }

  condition:
    any of them
}