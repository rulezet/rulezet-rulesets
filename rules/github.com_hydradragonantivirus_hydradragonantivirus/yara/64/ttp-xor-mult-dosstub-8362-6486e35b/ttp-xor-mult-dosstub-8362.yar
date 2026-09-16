rule TTP_XOR_MULT_DOSStub_8362 {
  strings:
    $key_8362 = { d7 0a [2] a3 12 [2] e4 10 [2] a3 01 [2] ed 0d [2] e1 07 [2] f6 0c [2] ed 42 [2] d0 }

  condition:
    any of them
}