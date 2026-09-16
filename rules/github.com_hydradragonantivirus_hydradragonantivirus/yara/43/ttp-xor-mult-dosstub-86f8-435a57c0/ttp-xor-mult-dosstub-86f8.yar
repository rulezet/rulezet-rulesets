rule TTP_XOR_MULT_DOSStub_86f8 {
  strings:
    $key_86f8 = { d2 90 [2] a6 88 [2] e1 8a [2] a6 9b [2] e8 97 [2] e4 9d [2] f3 96 [2] e8 d8 [2] d5 }

  condition:
    any of them
}