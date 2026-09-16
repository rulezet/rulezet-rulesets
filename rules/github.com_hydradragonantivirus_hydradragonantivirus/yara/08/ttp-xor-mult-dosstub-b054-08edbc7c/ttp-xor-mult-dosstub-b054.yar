rule TTP_XOR_MULT_DOSStub_b054 {
  strings:
    $key_b054 = { e4 3c [2] 90 24 [2] d7 26 [2] 90 37 [2] de 3b [2] d2 31 [2] c5 3a [2] de 74 [2] e3 }

  condition:
    any of them
}