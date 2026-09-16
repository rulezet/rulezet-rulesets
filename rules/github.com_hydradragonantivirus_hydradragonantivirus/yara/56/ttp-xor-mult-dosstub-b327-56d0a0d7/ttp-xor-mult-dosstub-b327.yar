rule TTP_XOR_MULT_DOSStub_b327 {
  strings:
    $key_b327 = { e7 4f [2] 93 57 [2] d4 55 [2] 93 44 [2] dd 48 [2] d1 42 [2] c6 49 [2] dd 07 [2] e0 }

  condition:
    any of them
}