rule TTP_XOR_QUAD_CurrentVersionRun_6378 {
  strings:
    $key_6378 = { 30 17 [2] 14 19 [2] 3f 35 [2] 11 17 [2] 05 0c [2] 0a 16 [2] 14 0b [2] 16 0a [2] 0d 0c [2] 11 0b [2] 0d 24 }

  condition:
    any of them
}