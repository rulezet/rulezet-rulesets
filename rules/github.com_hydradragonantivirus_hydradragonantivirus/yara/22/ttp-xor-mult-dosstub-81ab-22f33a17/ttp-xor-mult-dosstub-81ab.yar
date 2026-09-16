rule TTP_XOR_MULT_DOSStub_81ab {
  strings:
    $key_81ab = { d5 c3 [2] a1 db [2] e6 d9 [2] a1 c8 [2] ef c4 [2] e3 ce [2] f4 c5 [2] ef 8b [2] d2 }

  condition:
    any of them
}