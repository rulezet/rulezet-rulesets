rule TTP_XOR_MULT_DOSStub_b356 {
  strings:
    $key_b356 = { e7 3e [2] 93 26 [2] d4 24 [2] 93 35 [2] dd 39 [2] d1 33 [2] c6 38 [2] dd 76 [2] e0 }

  condition:
    any of them
}