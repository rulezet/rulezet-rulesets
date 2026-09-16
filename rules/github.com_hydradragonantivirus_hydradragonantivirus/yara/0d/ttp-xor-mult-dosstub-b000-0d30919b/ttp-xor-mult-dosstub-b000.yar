rule TTP_XOR_MULT_DOSStub_b000 {
  strings:
    $key_b000 = { e4 68 [2] 90 70 [2] d7 72 [2] 90 63 [2] de 6f [2] d2 65 [2] c5 6e [2] de 20 [2] e3 }

  condition:
    any of them
}