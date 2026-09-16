rule TTP_XOR_MULT_DOSStub_c9be {
  strings:
    $key_c9be = { 9d d6 [2] e9 ce [2] ae cc [2] e9 dd [2] a7 d1 [2] ab db [2] bc d0 [2] a7 9e [2] 9a }

  condition:
    any of them
}