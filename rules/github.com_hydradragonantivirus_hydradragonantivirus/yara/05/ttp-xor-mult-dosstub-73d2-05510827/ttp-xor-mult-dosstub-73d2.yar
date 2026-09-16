rule TTP_XOR_MULT_DOSStub_73d2 {
  strings:
    $key_73d2 = { 27 ba [2] 53 a2 [2] 14 a0 [2] 53 b1 [2] 1d bd [2] 11 b7 [2] 06 bc [2] 1d f2 [2] 20 }

  condition:
    any of them
}