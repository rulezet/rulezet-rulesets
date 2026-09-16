rule TTP_XOR_QUAD_CurrentVersionRun_7114 {
  strings:
    $key_7114 = { 22 7b [2] 06 75 [2] 2d 59 [2] 03 7b [2] 17 60 [2] 18 7a [2] 06 67 [2] 04 66 [2] 1f 60 [2] 03 67 [2] 1f 48 }

  condition:
    any of them
}