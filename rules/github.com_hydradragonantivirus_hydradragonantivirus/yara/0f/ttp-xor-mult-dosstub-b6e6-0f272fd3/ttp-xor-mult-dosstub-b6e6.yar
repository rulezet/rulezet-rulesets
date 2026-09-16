rule TTP_XOR_MULT_DOSStub_b6e6 {
  strings:
    $key_b6e6 = { e2 8e [2] 96 96 [2] d1 94 [2] 96 85 [2] d8 89 [2] d4 83 [2] c3 88 [2] d8 c6 [2] e5 }

  condition:
    any of them
}