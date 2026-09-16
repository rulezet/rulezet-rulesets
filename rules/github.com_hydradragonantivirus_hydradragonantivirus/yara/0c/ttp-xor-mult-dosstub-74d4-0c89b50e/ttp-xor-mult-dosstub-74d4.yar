rule TTP_XOR_MULT_DOSStub_74d4 {
  strings:
    $key_74d4 = { 20 bc [2] 54 a4 [2] 13 a6 [2] 54 b7 [2] 1a bb [2] 16 b1 [2] 01 ba [2] 1a f4 [2] 27 }

  condition:
    any of them
}