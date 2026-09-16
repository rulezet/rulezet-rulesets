rule TTP_XOR_MULT_DOSStub_79b3 {
  strings:
    $key_79b3 = { 2d db [2] 59 c3 [2] 1e c1 [2] 59 d0 [2] 17 dc [2] 1b d6 [2] 0c dd [2] 17 93 [2] 2a }

  condition:
    any of them
}