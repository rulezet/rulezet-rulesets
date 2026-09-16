rule TTP_XOR_MULT_DOSStub_8dad {
  strings:
    $key_8dad = { d9 c5 [2] ad dd [2] ea df [2] ad ce [2] e3 c2 [2] ef c8 [2] f8 c3 [2] e3 8d [2] de }

  condition:
    any of them
}