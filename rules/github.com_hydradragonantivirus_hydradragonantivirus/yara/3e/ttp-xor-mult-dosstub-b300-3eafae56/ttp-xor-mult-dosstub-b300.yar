rule TTP_XOR_MULT_DOSStub_b300 {
  strings:
    $key_b300 = { e7 68 [2] 93 70 [2] d4 72 [2] 93 63 [2] dd 6f [2] d1 65 [2] c6 6e [2] dd 20 [2] e0 }

  condition:
    any of them
}