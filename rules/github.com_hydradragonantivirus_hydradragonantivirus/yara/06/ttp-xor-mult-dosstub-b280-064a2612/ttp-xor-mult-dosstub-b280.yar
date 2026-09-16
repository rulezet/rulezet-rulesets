rule TTP_XOR_MULT_DOSStub_b280 {
  strings:
    $key_b280 = { e6 e8 [2] 92 f0 [2] d5 f2 [2] 92 e3 [2] dc ef [2] d0 e5 [2] c7 ee [2] dc a0 [2] e1 }

  condition:
    any of them
}