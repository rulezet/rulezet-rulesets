rule TTP_XOR_QUAD_CurrentVersionRun_5654 {
  strings:
    $key_5654 = { 05 3b [2] 21 35 [2] 0a 19 [2] 24 3b [2] 30 20 [2] 3f 3a [2] 21 27 [2] 23 26 [2] 38 20 [2] 24 27 [2] 38 08 }

  condition:
    any of them
}