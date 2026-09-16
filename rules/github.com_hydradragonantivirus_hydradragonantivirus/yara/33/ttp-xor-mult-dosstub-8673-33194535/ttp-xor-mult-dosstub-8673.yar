rule TTP_XOR_MULT_DOSStub_8673 {
  strings:
    $key_8673 = { d2 1b [2] a6 03 [2] e1 01 [2] a6 10 [2] e8 1c [2] e4 16 [2] f3 1d [2] e8 53 [2] d5 }

  condition:
    any of them
}