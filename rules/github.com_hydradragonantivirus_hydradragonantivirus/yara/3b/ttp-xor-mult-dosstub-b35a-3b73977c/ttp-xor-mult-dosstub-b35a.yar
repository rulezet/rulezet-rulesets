rule TTP_XOR_MULT_DOSStub_b35a {
  strings:
    $key_b35a = { e7 32 [2] 93 2a [2] d4 28 [2] 93 39 [2] dd 35 [2] d1 3f [2] c6 34 [2] dd 7a [2] e0 }

  condition:
    any of them
}