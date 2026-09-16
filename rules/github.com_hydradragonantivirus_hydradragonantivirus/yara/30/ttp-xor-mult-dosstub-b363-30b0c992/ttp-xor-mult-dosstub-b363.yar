rule TTP_XOR_MULT_DOSStub_b363 {
  strings:
    $key_b363 = { e7 0b [2] 93 13 [2] d4 11 [2] 93 00 [2] dd 0c [2] d1 06 [2] c6 0d [2] dd 43 [2] e0 }

  condition:
    any of them
}