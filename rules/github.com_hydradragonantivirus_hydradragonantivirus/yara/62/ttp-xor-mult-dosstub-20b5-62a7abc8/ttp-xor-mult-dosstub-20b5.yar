rule TTP_XOR_MULT_DOSStub_20b5 {
  strings:
    $key_20b5 = { 74 dd [2] 00 c5 [2] 47 c7 [2] 00 d6 [2] 4e da [2] 42 d0 [2] 55 db [2] 4e 95 [2] 73 }

  condition:
    any of them
}