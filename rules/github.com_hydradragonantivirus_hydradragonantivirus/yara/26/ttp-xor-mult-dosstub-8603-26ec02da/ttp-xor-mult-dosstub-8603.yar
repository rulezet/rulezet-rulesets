rule TTP_XOR_MULT_DOSStub_8603 {
  strings:
    $key_8603 = { d2 6b [2] a6 73 [2] e1 71 [2] a6 60 [2] e8 6c [2] e4 66 [2] f3 6d [2] e8 23 [2] d5 }

  condition:
    any of them
}