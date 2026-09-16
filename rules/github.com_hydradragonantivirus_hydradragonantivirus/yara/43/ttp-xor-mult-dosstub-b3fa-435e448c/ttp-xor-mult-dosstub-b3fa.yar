rule TTP_XOR_MULT_DOSStub_b3fa {
  strings:
    $key_b3fa = { e7 92 [2] 93 8a [2] d4 88 [2] 93 99 [2] dd 95 [2] d1 9f [2] c6 94 [2] dd da [2] e0 }

  condition:
    any of them
}