rule TTP_XOR_MULT_DOSStub_8622 {
  strings:
    $key_8622 = { d2 4a [2] a6 52 [2] e1 50 [2] a6 41 [2] e8 4d [2] e4 47 [2] f3 4c [2] e8 02 [2] d5 }

  condition:
    any of them
}