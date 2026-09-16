rule TTP_XOR_QUAD_CurrentVersionRun_7168 {
  strings:
    $key_7168 = { 22 07 [2] 06 09 [2] 2d 25 [2] 03 07 [2] 17 1c [2] 18 06 [2] 06 1b [2] 04 1a [2] 1f 1c [2] 03 1b [2] 1f 34 }

  condition:
    any of them
}