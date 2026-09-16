rule TTP_XOR_MULT_DOSStub_95f8 {
  strings:
    $key_95f8 = { c1 90 [2] b5 88 [2] f2 8a [2] b5 9b [2] fb 97 [2] f7 9d [2] e0 96 [2] fb d8 [2] c6 }

  condition:
    any of them
}