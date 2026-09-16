rule TTP_XOR_QUAD_CurrentVersionRun_4406 {
  strings:
    $key_4406 = { 17 69 [2] 33 67 [2] 18 4b [2] 36 69 [2] 22 72 [2] 2d 68 [2] 33 75 [2] 31 74 [2] 2a 72 [2] 36 75 [2] 2a 5a }

  condition:
    any of them
}