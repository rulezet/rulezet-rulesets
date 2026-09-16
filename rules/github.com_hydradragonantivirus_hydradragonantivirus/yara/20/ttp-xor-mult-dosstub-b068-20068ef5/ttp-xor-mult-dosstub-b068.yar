rule TTP_XOR_MULT_DOSStub_b068 {
  strings:
    $key_b068 = { e4 00 [2] 90 18 [2] d7 1a [2] 90 0b [2] de 07 [2] d2 0d [2] c5 06 [2] de 48 [2] e3 }

  condition:
    any of them
}