rule TTP_XOR_MULT_DOSStub_b686 {
  strings:
    $key_b686 = { e2 ee [2] 96 f6 [2] d1 f4 [2] 96 e5 [2] d8 e9 [2] d4 e3 [2] c3 e8 [2] d8 a6 [2] e5 }

  condition:
    any of them
}