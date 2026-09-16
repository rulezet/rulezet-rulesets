rule TTP_XOR_MULT_DOSStub_b3e2 {
  strings:
    $key_b3e2 = { e7 8a [2] 93 92 [2] d4 90 [2] 93 81 [2] dd 8d [2] d1 87 [2] c6 8c [2] dd c2 [2] e0 }

  condition:
    any of them
}