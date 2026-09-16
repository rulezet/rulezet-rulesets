rule TTP_XOR_MULT_DOSStub_83e5 {
  strings:
    $key_83e5 = { d7 8d [2] a3 95 [2] e4 97 [2] a3 86 [2] ed 8a [2] e1 80 [2] f6 8b [2] ed c5 [2] d0 }

  condition:
    any of them
}