rule TTP_XOR_MULT_DOSStub_b321 {
  strings:
    $key_b321 = { e7 49 [2] 93 51 [2] d4 53 [2] 93 42 [2] dd 4e [2] d1 44 [2] c6 4f [2] dd 01 [2] e0 }

  condition:
    any of them
}