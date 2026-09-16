rule TTP_XOR_MULT_DOSStub_b7d0 {
  strings:
    $key_b7d0 = { e3 b8 [2] 97 a0 [2] d0 a2 [2] 97 b3 [2] d9 bf [2] d5 b5 [2] c2 be [2] d9 f0 [2] e4 }

  condition:
    any of them
}