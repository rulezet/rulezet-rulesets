rule TTP_XOR_MULT_DOSStub_74d2 {
  strings:
    $key_74d2 = { 20 ba [2] 54 a2 [2] 13 a0 [2] 54 b1 [2] 1a bd [2] 16 b7 [2] 01 bc [2] 1a f2 [2] 27 }

  condition:
    any of them
}