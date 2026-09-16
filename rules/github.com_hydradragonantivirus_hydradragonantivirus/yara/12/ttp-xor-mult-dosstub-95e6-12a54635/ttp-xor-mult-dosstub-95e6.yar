rule TTP_XOR_MULT_DOSStub_95e6 {
  strings:
    $key_95e6 = { c1 8e [2] b5 96 [2] f2 94 [2] b5 85 [2] fb 89 [2] f7 83 [2] e0 88 [2] fb c6 [2] c6 }

  condition:
    any of them
}