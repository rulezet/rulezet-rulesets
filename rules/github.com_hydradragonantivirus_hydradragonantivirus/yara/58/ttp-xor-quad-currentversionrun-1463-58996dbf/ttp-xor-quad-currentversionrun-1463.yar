rule TTP_XOR_QUAD_CurrentVersionRun_1463 {
  strings:
    $key_1463 = { 47 0c [2] 63 02 [2] 48 2e [2] 66 0c [2] 72 17 [2] 7d 0d [2] 63 10 [2] 61 11 [2] 7a 17 [2] 66 10 [2] 7a 3f }

  condition:
    any of them
}