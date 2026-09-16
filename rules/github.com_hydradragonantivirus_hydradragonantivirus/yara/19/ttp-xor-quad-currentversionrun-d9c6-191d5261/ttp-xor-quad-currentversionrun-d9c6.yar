rule TTP_XOR_QUAD_CurrentVersionRun_d9c6 {
  strings:
    $key_d9c6 = { 8a a9 [2] ae a7 [2] 85 8b [2] ab a9 [2] bf b2 [2] b0 a8 [2] ae b5 [2] ac b4 [2] b7 b2 [2] ab b5 [2] b7 9a }

  condition:
    any of them
}