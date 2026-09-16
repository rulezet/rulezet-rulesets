rule TTP_XOR_MULT_DOSStub_b672 {
  strings:
    $key_b672 = { e2 1a [2] 96 02 [2] d1 00 [2] 96 11 [2] d8 1d [2] d4 17 [2] c3 1c [2] d8 52 [2] e5 }

  condition:
    any of them
}