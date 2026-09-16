rule TTP_XOR_MULT_DOSStub_8653 {
  strings:
    $key_8653 = { d2 3b [2] a6 23 [2] e1 21 [2] a6 30 [2] e8 3c [2] e4 36 [2] f3 3d [2] e8 73 [2] d5 }

  condition:
    any of them
}