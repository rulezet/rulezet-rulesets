rule TTP_XOR_MULT_DOSStub_b320 {
  strings:
    $key_b320 = { e7 48 [2] 93 50 [2] d4 52 [2] 93 43 [2] dd 4f [2] d1 45 [2] c6 4e [2] dd 00 [2] e0 }

  condition:
    any of them
}