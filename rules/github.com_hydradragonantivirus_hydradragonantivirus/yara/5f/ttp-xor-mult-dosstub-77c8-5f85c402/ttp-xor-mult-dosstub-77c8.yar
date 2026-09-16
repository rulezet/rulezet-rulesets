rule TTP_XOR_MULT_DOSStub_77c8 {
  strings:
    $key_77c8 = { 23 a0 [2] 57 b8 [2] 10 ba [2] 57 ab [2] 19 a7 [2] 15 ad [2] 02 a6 [2] 19 e8 [2] 24 }

  condition:
    any of them
}