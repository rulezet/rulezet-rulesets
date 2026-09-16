rule TTP_XOR_MULT_DOSStub_b681 {
  strings:
    $key_b681 = { e2 e9 [2] 96 f1 [2] d1 f3 [2] 96 e2 [2] d8 ee [2] d4 e4 [2] c3 ef [2] d8 a1 [2] e5 }

  condition:
    any of them
}