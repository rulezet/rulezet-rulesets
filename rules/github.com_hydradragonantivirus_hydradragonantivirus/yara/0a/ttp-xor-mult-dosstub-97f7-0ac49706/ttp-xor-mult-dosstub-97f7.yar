rule TTP_XOR_MULT_DOSStub_97f7 {
  strings:
    $key_97f7 = { c3 9f [2] b7 87 [2] f0 85 [2] b7 94 [2] f9 98 [2] f5 92 [2] e2 99 [2] f9 d7 [2] c4 }

  condition:
    any of them
}