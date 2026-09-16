rule TTP_XOR_MULT_DOSStub_b063 {
  strings:
    $key_b063 = { e4 0b [2] 90 13 [2] d7 11 [2] 90 00 [2] de 0c [2] d2 06 [2] c5 0d [2] de 43 [2] e3 }

  condition:
    any of them
}