rule TTP_XOR_QUAD_CurrentVersionRun_7178 {
  strings:
    $key_7178 = { 22 17 [2] 06 19 [2] 2d 35 [2] 03 17 [2] 17 0c [2] 18 16 [2] 06 0b [2] 04 0a [2] 1f 0c [2] 03 0b [2] 1f 24 }

  condition:
    any of them
}