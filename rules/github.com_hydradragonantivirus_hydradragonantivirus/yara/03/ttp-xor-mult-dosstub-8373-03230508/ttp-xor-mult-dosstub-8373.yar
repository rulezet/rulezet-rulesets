rule TTP_XOR_MULT_DOSStub_8373 {
  strings:
    $key_8373 = { d7 1b [2] a3 03 [2] e4 01 [2] a3 10 [2] ed 1c [2] e1 16 [2] f6 1d [2] ed 53 [2] d0 }

  condition:
    any of them
}