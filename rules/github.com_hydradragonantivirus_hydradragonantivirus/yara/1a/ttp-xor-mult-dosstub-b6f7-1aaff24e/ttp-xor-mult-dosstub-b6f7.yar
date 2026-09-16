rule TTP_XOR_MULT_DOSStub_b6f7 {
  strings:
    $key_b6f7 = { e2 9f [2] 96 87 [2] d1 85 [2] 96 94 [2] d8 98 [2] d4 92 [2] c3 99 [2] d8 d7 [2] e5 }

  condition:
    any of them
}