rule TTP_XOR_QUAD_CurrentVersionRun_1354 {
  strings:
    $key_1354 = { 40 3b [2] 64 35 [2] 4f 19 [2] 61 3b [2] 75 20 [2] 7a 3a [2] 64 27 [2] 66 26 [2] 7d 20 [2] 61 27 [2] 7d 08 }

  condition:
    any of them
}