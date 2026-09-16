rule TTP_XOR_MULT_DOSStub_b351 {
  strings:
    $key_b351 = { e7 39 [2] 93 21 [2] d4 23 [2] 93 32 [2] dd 3e [2] d1 34 [2] c6 3f [2] dd 71 [2] e0 }

  condition:
    any of them
}