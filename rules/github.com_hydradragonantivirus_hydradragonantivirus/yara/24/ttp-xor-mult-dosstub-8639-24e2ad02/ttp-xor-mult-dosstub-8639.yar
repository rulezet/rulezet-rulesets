rule TTP_XOR_MULT_DOSStub_8639 {
  strings:
    $key_8639 = { d2 51 [2] a6 49 [2] e1 4b [2] a6 5a [2] e8 56 [2] e4 5c [2] f3 57 [2] e8 19 [2] d5 }

  condition:
    any of them
}