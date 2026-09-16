rule TTP_XOR_MULT_DOSStub_81a9 {
  strings:
    $key_81a9 = { d5 c1 [2] a1 d9 [2] e6 db [2] a1 ca [2] ef c6 [2] e3 cc [2] f4 c7 [2] ef 89 [2] d2 }

  condition:
    any of them
}