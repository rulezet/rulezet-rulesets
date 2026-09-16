rule TTP_XOR_QUAD_CurrentVersionRun_7176 {
  strings:
    $key_7176 = { 22 19 [2] 06 17 [2] 2d 3b [2] 03 19 [2] 17 02 [2] 18 18 [2] 06 05 [2] 04 04 [2] 1f 02 [2] 03 05 [2] 1f 2a }

  condition:
    any of them
}