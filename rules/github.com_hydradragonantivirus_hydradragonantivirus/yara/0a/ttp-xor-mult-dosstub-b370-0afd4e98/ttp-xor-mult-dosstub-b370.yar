rule TTP_XOR_MULT_DOSStub_b370 {
  strings:
    $key_b370 = { e7 18 [2] 93 00 [2] d4 02 [2] 93 13 [2] dd 1f [2] d1 15 [2] c6 1e [2] dd 50 [2] e0 }

  condition:
    any of them
}