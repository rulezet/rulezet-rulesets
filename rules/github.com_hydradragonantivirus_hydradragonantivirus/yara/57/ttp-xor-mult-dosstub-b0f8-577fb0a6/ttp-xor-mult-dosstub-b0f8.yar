rule TTP_XOR_MULT_DOSStub_b0f8 {
  strings:
    $key_b0f8 = { e4 90 [2] 90 88 [2] d7 8a [2] 90 9b [2] de 97 [2] d2 9d [2] c5 96 [2] de d8 [2] e3 }

  condition:
    any of them
}