rule TTP_XOR_MULT_DOSStub_83f9 {
  strings:
    $key_83f9 = { d7 91 [2] a3 89 [2] e4 8b [2] a3 9a [2] ed 96 [2] e1 9c [2] f6 97 [2] ed d9 [2] d0 }

  condition:
    any of them
}