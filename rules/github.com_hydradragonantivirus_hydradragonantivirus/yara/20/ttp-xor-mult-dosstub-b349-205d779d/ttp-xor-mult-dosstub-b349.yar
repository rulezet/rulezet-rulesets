rule TTP_XOR_MULT_DOSStub_b349 {
  strings:
    $key_b349 = { e7 21 [2] 93 39 [2] d4 3b [2] 93 2a [2] dd 26 [2] d1 2c [2] c6 27 [2] dd 69 [2] e0 }

  condition:
    any of them
}