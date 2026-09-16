rule TTP_XOR_MULT_DOSStub_8359 {
  strings:
    $key_8359 = { d7 31 [2] a3 29 [2] e4 2b [2] a3 3a [2] ed 36 [2] e1 3c [2] f6 37 [2] ed 79 [2] d0 }

  condition:
    any of them
}