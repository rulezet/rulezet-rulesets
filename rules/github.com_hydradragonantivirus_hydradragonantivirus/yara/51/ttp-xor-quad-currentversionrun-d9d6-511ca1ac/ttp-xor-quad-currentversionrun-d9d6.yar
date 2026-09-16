rule TTP_XOR_QUAD_CurrentVersionRun_d9d6 {
  strings:
    $key_d9d6 = { 8a b9 [2] ae b7 [2] 85 9b [2] ab b9 [2] bf a2 [2] b0 b8 [2] ae a5 [2] ac a4 [2] b7 a2 [2] ab a5 [2] b7 8a }

  condition:
    any of them
}