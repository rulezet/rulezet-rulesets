rule TTP_XOR_MULT_DOSStub_b6e0 {
  strings:
    $key_b6e0 = { e2 88 [2] 96 90 [2] d1 92 [2] 96 83 [2] d8 8f [2] d4 85 [2] c3 8e [2] d8 c0 [2] e5 }

  condition:
    any of them
}