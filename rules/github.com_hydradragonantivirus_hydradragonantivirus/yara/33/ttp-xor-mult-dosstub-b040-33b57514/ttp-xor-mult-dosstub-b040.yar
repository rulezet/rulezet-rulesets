rule TTP_XOR_MULT_DOSStub_b040 {
  strings:
    $key_b040 = { e4 28 [2] 90 30 [2] d7 32 [2] 90 23 [2] de 2f [2] d2 25 [2] c5 2e [2] de 60 [2] e3 }

  condition:
    any of them
}