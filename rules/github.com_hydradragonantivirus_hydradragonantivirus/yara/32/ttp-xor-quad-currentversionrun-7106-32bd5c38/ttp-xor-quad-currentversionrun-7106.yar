rule TTP_XOR_QUAD_CurrentVersionRun_7106 {
  strings:
    $key_7106 = { 22 69 [2] 06 67 [2] 2d 4b [2] 03 69 [2] 17 72 [2] 18 68 [2] 06 75 [2] 04 74 [2] 1f 72 [2] 03 75 [2] 1f 5a }

  condition:
    any of them
}