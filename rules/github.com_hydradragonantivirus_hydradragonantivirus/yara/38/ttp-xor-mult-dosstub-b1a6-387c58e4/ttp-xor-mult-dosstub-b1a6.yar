rule TTP_XOR_MULT_DOSStub_b1a6 {
  strings:
    $key_b1a6 = { e5 ce [2] 91 d6 [2] d6 d4 [2] 91 c5 [2] df c9 [2] d3 c3 [2] c4 c8 [2] df 86 [2] e2 }

  condition:
    any of them
}