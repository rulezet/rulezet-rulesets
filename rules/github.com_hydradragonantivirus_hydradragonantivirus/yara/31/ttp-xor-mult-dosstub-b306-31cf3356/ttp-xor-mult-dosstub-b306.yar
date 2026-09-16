rule TTP_XOR_MULT_DOSStub_b306 {
  strings:
    $key_b306 = { e7 6e [2] 93 76 [2] d4 74 [2] 93 65 [2] dd 69 [2] d1 63 [2] c6 68 [2] dd 26 [2] e0 }

  condition:
    any of them
}