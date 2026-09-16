rule TTP_XOR_QUAD_CurrentVersionRun_0263 {
  strings:
    $key_0263 = { 51 0c [2] 75 02 [2] 5e 2e [2] 70 0c [2] 64 17 [2] 6b 0d [2] 75 10 [2] 77 11 [2] 6c 17 [2] 70 10 [2] 6c 3f }

  condition:
    any of them
}