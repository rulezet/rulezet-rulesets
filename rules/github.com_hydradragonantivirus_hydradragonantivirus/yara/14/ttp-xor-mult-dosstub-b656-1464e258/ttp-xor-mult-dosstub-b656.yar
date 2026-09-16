rule TTP_XOR_MULT_DOSStub_b656 {
  strings:
    $key_b656 = { e2 3e [2] 96 26 [2] d1 24 [2] 96 35 [2] d8 39 [2] d4 33 [2] c3 38 [2] d8 76 [2] e5 }

  condition:
    any of them
}