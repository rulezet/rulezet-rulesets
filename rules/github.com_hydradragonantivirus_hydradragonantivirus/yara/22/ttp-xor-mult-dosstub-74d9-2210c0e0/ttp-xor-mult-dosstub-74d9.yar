rule TTP_XOR_MULT_DOSStub_74d9 {
  strings:
    $key_74d9 = { 20 b1 [2] 54 a9 [2] 13 ab [2] 54 ba [2] 1a b6 [2] 16 bc [2] 01 b7 [2] 1a f9 [2] 27 }

  condition:
    any of them
}