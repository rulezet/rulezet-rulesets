rule TTP_XOR_MULT_DOSStub_b049 {
  strings:
    $key_b049 = { e4 21 [2] 90 39 [2] d7 3b [2] 90 2a [2] de 26 [2] d2 2c [2] c5 27 [2] de 69 [2] e3 }

  condition:
    any of them
}