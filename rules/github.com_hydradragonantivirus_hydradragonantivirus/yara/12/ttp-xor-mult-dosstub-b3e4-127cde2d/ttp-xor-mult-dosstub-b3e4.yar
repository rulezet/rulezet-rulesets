rule TTP_XOR_MULT_DOSStub_b3e4 {
  strings:
    $key_b3e4 = { e7 8c [2] 93 94 [2] d4 96 [2] 93 87 [2] dd 8b [2] d1 81 [2] c6 8a [2] dd c4 [2] e0 }

  condition:
    any of them
}