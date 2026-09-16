rule TTP_XOR_MULT_DOSStub_8332 {
  strings:
    $key_8332 = { d7 5a [2] a3 42 [2] e4 40 [2] a3 51 [2] ed 5d [2] e1 57 [2] f6 5c [2] ed 12 [2] d0 }

  condition:
    any of them
}