rule TTP_XOR_QUAD_CurrentVersionRun_dcc7 {
  strings:
    $key_dcc7 = { 8f a8 [2] ab a6 [2] 80 8a [2] ae a8 [2] ba b3 [2] b5 a9 [2] ab b4 [2] a9 b5 [2] b2 b3 [2] ae b4 [2] b2 9b }

  condition:
    any of them
}