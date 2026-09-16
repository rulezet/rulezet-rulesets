rule TTP_XOR_QUAD_CurrentVersionRun_5158 {
  strings:
    $key_5158 = { 02 37 [2] 26 39 [2] 0d 15 [2] 23 37 [2] 37 2c [2] 38 36 [2] 26 2b [2] 24 2a [2] 3f 2c [2] 23 2b [2] 3f 04 }

  condition:
    any of them
}