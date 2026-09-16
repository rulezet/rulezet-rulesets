rule TTP_XOR_QUAD_CurrentVersionRun_6806 {
  strings:
    $key_6806 = { 3b 69 [2] 1f 67 [2] 34 4b [2] 1a 69 [2] 0e 72 [2] 01 68 [2] 1f 75 [2] 1d 74 [2] 06 72 [2] 1a 75 [2] 06 5a }

  condition:
    any of them
}