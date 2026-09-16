rule TTP_XOR_QUAD_CurrentVersionRun_4163 {
  strings:
    $key_4163 = { 12 0c [2] 36 02 [2] 1d 2e [2] 33 0c [2] 27 17 [2] 28 0d [2] 36 10 [2] 34 11 [2] 2f 17 [2] 33 10 [2] 2f 3f }

  condition:
    any of them
}