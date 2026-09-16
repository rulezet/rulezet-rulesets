rule TTP_XOR_MULT_DOSStub_47c8 {
  strings:
    $key_47c8 = { 13 a0 [2] 67 b8 [2] 20 ba [2] 67 ab [2] 29 a7 [2] 25 ad [2] 32 a6 [2] 29 e8 [2] 14 }

  condition:
    any of them
}