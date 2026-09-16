rule TTP_XOR_QUAD_CurrentVersionRun_d9c7 {
  strings:
    $key_d9c7 = { 8a a8 [2] ae a6 [2] 85 8a [2] ab a8 [2] bf b3 [2] b0 a9 [2] ae b4 [2] ac b5 [2] b7 b3 [2] ab b4 [2] b7 9b }

  condition:
    any of them
}