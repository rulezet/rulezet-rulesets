rule TTP_XOR_MULT_DOSStub_73d9 {
  strings:
    $key_73d9 = { 27 b1 [2] 53 a9 [2] 14 ab [2] 53 ba [2] 1d b6 [2] 11 bc [2] 06 b7 [2] 1d f9 [2] 20 }

  condition:
    any of them
}