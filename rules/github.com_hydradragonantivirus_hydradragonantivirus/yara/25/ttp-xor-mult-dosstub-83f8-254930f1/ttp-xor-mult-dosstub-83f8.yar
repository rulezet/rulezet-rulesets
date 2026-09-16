rule TTP_XOR_MULT_DOSStub_83f8 {
  strings:
    $key_83f8 = { d7 90 [2] a3 88 [2] e4 8a [2] a3 9b [2] ed 97 [2] e1 9d [2] f6 96 [2] ed d8 [2] d0 }

  condition:
    any of them
}