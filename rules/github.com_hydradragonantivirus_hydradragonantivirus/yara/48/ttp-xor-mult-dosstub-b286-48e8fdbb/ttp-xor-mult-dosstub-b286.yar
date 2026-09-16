rule TTP_XOR_MULT_DOSStub_b286 {
  strings:
    $key_b286 = { e6 ee [2] 92 f6 [2] d5 f4 [2] 92 e5 [2] dc e9 [2] d0 e3 [2] c7 e8 [2] dc a6 [2] e1 }

  condition:
    any of them
}