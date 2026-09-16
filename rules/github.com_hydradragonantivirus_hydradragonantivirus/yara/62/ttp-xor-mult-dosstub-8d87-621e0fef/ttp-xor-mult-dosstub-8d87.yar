rule TTP_XOR_MULT_DOSStub_8d87 {
  strings:
    $key_8d87 = { d9 ef [2] ad f7 [2] ea f5 [2] ad e4 [2] e3 e8 [2] ef e2 [2] f8 e9 [2] e3 a7 [2] de }

  condition:
    any of them
}