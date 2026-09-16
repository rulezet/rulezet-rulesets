rule TTP_XOR_MULT_DOSStub_b641 {
  strings:
    $key_b641 = { e2 29 [2] 96 31 [2] d1 33 [2] 96 22 [2] d8 2e [2] d4 24 [2] c3 2f [2] d8 61 [2] e5 }

  condition:
    any of them
}