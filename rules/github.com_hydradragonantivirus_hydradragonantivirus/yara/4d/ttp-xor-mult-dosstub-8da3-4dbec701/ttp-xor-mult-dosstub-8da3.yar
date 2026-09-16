rule TTP_XOR_MULT_DOSStub_8da3 {
  strings:
    $key_8da3 = { d9 cb [2] ad d3 [2] ea d1 [2] ad c0 [2] e3 cc [2] ef c6 [2] f8 cd [2] e3 83 [2] de }

  condition:
    any of them
}