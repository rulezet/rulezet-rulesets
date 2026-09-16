rule TTP_XOR_MULT_DOSStub_8616 {
  strings:
    $key_8616 = { d2 7e [2] a6 66 [2] e1 64 [2] a6 75 [2] e8 79 [2] e4 73 [2] f3 78 [2] e8 36 [2] d5 }

  condition:
    any of them
}