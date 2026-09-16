rule TTP_XOR_QUAD_CurrentVersionRun_d9d7 {
  strings:
    $key_d9d7 = { 8a b8 [2] ae b6 [2] 85 9a [2] ab b8 [2] bf a3 [2] b0 b9 [2] ae a4 [2] ac a5 [2] b7 a3 [2] ab a4 [2] b7 8b }

  condition:
    any of them
}