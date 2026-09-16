rule TTP_XOR_MULT_DOSStub_b072 {
  strings:
    $key_b072 = { e4 1a [2] 90 02 [2] d7 00 [2] 90 11 [2] de 1d [2] d2 17 [2] c5 1c [2] de 52 [2] e3 }

  condition:
    any of them
}