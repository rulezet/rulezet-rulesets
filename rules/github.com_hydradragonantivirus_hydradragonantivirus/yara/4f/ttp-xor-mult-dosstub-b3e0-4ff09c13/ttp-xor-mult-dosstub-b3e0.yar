rule TTP_XOR_MULT_DOSStub_b3e0 {
  strings:
    $key_b3e0 = { e7 88 [2] 93 90 [2] d4 92 [2] 93 83 [2] dd 8f [2] d1 85 [2] c6 8e [2] dd c0 [2] e0 }

  condition:
    any of them
}