rule TTP_XOR_MULT_DOSStub_b1b9 {
  strings:
    $key_b1b9 = { e5 d1 [2] 91 c9 [2] d6 cb [2] 91 da [2] df d6 [2] d3 dc [2] c4 d7 [2] df 99 [2] e2 }

  condition:
    any of them
}