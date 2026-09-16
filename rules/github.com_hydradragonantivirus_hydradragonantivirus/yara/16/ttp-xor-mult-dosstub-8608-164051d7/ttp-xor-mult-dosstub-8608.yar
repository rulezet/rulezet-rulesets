rule TTP_XOR_MULT_DOSStub_8608 {
  strings:
    $key_8608 = { d2 60 [2] a6 78 [2] e1 7a [2] a6 6b [2] e8 67 [2] e4 6d [2] f3 66 [2] e8 28 [2] d5 }

  condition:
    any of them
}