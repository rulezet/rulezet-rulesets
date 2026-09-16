rule TTP_XOR_QUAD_CurrentVersionRun_d9d4 {
  strings:
    $key_d9d4 = { 8a bb [2] ae b5 [2] 85 99 [2] ab bb [2] bf a0 [2] b0 ba [2] ae a7 [2] ac a6 [2] b7 a0 [2] ab a7 [2] b7 88 }

  condition:
    any of them
}