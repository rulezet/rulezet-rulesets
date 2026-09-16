rule TTP_XOR_MULT_DOSStub_b015 {
  strings:
    $key_b015 = { e4 7d [2] 90 65 [2] d7 67 [2] 90 76 [2] de 7a [2] d2 70 [2] c5 7b [2] de 35 [2] e3 }

  condition:
    any of them
}