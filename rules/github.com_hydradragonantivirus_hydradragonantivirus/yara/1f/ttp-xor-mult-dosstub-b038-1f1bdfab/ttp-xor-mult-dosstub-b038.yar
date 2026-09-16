rule TTP_XOR_MULT_DOSStub_b038 {
  strings:
    $key_b038 = { e4 50 [2] 90 48 [2] d7 4a [2] 90 5b [2] de 57 [2] d2 5d [2] c5 56 [2] de 18 [2] e3 }

  condition:
    any of them
}