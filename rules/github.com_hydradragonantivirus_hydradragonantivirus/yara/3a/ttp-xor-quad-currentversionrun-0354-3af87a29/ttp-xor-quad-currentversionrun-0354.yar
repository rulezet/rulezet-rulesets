rule TTP_XOR_QUAD_CurrentVersionRun_0354 {
  strings:
    $key_0354 = { 50 3b [2] 74 35 [2] 5f 19 [2] 71 3b [2] 65 20 [2] 6a 3a [2] 74 27 [2] 76 26 [2] 6d 20 [2] 71 27 [2] 6d 08 }

  condition:
    any of them
}