rule TTP_XOR_MULT_DOSStub_b357 {
  strings:
    $key_b357 = { e7 3f [2] 93 27 [2] d4 25 [2] 93 34 [2] dd 38 [2] d1 32 [2] c6 39 [2] dd 77 [2] e0 }

  condition:
    any of them
}