rule TTP_XOR_MULT_DOSStub_b350 {
  strings:
    $key_b350 = { e7 38 [2] 93 20 [2] d4 22 [2] 93 33 [2] dd 3f [2] d1 35 [2] c6 3e [2] dd 70 [2] e0 }

  condition:
    any of them
}