rule TTP_XOR_QUAD_CurrentVersionRun_d9c5 {
  strings:
    $key_d9c5 = { 8a aa [2] ae a4 [2] 85 88 [2] ab aa [2] bf b1 [2] b0 ab [2] ae b6 [2] ac b7 [2] b7 b1 [2] ab b6 [2] b7 99 }

  condition:
    any of them
}