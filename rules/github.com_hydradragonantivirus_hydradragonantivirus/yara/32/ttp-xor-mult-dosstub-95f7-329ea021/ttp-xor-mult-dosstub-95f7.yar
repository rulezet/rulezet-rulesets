rule TTP_XOR_MULT_DOSStub_95f7 {
  strings:
    $key_95f7 = { c1 9f [2] b5 87 [2] f2 85 [2] b5 94 [2] fb 98 [2] f7 92 [2] e0 99 [2] fb d7 [2] c6 }

  condition:
    any of them
}