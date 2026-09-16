rule TTP_XOR_MULT_DOSStub_b012 {
  strings:
    $key_b012 = { e4 7a [2] 90 62 [2] d7 60 [2] 90 71 [2] de 7d [2] d2 77 [2] c5 7c [2] de 32 [2] e3 }

  condition:
    any of them
}