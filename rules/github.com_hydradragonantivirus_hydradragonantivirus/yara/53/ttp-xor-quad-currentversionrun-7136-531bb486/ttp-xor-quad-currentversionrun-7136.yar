rule TTP_XOR_QUAD_CurrentVersionRun_7136 {
  strings:
    $key_7136 = { 22 59 [2] 06 57 [2] 2d 7b [2] 03 59 [2] 17 42 [2] 18 58 [2] 06 45 [2] 04 44 [2] 1f 42 [2] 03 45 [2] 1f 6a }

  condition:
    any of them
}