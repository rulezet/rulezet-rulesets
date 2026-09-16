rule TTP_XOR_MULT_DOSStub_b5a6 {
  strings:
    $key_b5a6 = { e1 ce [2] 95 d6 [2] d2 d4 [2] 95 c5 [2] db c9 [2] d7 c3 [2] c0 c8 [2] db 86 [2] e6 }

  condition:
    any of them
}