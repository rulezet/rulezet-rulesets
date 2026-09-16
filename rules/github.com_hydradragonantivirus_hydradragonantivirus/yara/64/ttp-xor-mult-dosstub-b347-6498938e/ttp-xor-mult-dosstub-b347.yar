rule TTP_XOR_MULT_DOSStub_b347 {
  strings:
    $key_b347 = { e7 2f [2] 93 37 [2] d4 35 [2] 93 24 [2] dd 28 [2] d1 22 [2] c6 29 [2] dd 67 [2] e0 }

  condition:
    any of them
}