rule TTP_XOR_QUAD_CurrentVersionRun_7107 {
  strings:
    $key_7107 = { 22 68 [2] 06 66 [2] 2d 4a [2] 03 68 [2] 17 73 [2] 18 69 [2] 06 74 [2] 04 75 [2] 1f 73 [2] 03 74 [2] 1f 5b }

  condition:
    any of them
}