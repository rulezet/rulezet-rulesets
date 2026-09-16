rule TTP_XOR_QUAD_CurrentVersionRun_4116 {
  strings:
    $key_4116 = { 12 79 [2] 36 77 [2] 1d 5b [2] 33 79 [2] 27 62 [2] 28 78 [2] 36 65 [2] 34 64 [2] 2f 62 [2] 33 65 [2] 2f 4a }

  condition:
    any of them
}