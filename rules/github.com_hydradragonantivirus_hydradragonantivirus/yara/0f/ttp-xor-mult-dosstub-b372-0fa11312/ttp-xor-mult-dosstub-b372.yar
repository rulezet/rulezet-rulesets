rule TTP_XOR_MULT_DOSStub_b372 {
  strings:
    $key_b372 = { e7 1a [2] 93 02 [2] d4 00 [2] 93 11 [2] dd 1d [2] d1 17 [2] c6 1c [2] dd 52 [2] e0 }

  condition:
    any of them
}