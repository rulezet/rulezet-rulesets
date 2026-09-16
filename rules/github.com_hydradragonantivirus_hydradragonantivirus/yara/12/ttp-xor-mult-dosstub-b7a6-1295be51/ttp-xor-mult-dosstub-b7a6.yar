rule TTP_XOR_MULT_DOSStub_b7a6 {
  strings:
    $key_b7a6 = { e3 ce [2] 97 d6 [2] d0 d4 [2] 97 c5 [2] d9 c9 [2] d5 c3 [2] c2 c8 [2] d9 86 [2] e4 }

  condition:
    any of them
}