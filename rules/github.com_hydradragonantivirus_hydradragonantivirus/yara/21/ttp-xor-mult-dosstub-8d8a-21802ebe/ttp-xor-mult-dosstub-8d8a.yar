rule TTP_XOR_MULT_DOSStub_8d8a {
  strings:
    $key_8d8a = { d9 e2 [2] ad fa [2] ea f8 [2] ad e9 [2] e3 e5 [2] ef ef [2] f8 e4 [2] e3 aa [2] de }

  condition:
    any of them
}