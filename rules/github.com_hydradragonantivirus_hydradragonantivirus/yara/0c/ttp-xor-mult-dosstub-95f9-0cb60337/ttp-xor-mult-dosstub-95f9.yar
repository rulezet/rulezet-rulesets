rule TTP_XOR_MULT_DOSStub_95f9 {
  strings:
    $key_95f9 = { c1 91 [2] b5 89 [2] f2 8b [2] b5 9a [2] fb 96 [2] f7 9c [2] e0 97 [2] fb d9 [2] c6 }

  condition:
    any of them
}