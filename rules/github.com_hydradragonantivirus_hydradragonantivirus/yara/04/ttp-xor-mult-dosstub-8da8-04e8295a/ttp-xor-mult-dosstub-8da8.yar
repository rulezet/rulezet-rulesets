rule TTP_XOR_MULT_DOSStub_8da8 {
  strings:
    $key_8da8 = { d9 c0 [2] ad d8 [2] ea da [2] ad cb [2] e3 c7 [2] ef cd [2] f8 c6 [2] e3 88 [2] de }

  condition:
    any of them
}