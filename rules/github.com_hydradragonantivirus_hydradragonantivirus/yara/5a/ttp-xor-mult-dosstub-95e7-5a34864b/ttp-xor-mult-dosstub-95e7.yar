rule TTP_XOR_MULT_DOSStub_95e7 {
  strings:
    $key_95e7 = { c1 8f [2] b5 97 [2] f2 95 [2] b5 84 [2] fb 88 [2] f7 82 [2] e0 89 [2] fb c7 [2] c6 }

  condition:
    any of them
}