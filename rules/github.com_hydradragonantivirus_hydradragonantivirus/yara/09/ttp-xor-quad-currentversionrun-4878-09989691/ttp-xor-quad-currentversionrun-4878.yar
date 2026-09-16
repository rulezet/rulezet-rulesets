rule TTP_XOR_QUAD_CurrentVersionRun_4878 {
  strings:
    $key_4878 = { 1b 17 [2] 3f 19 [2] 14 35 [2] 3a 17 [2] 2e 0c [2] 21 16 [2] 3f 0b [2] 3d 0a [2] 26 0c [2] 3a 0b [2] 26 24 }

  condition:
    any of them
}