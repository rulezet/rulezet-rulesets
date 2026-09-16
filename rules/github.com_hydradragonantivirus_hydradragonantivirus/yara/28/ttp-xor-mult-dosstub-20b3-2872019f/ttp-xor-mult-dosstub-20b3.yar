rule TTP_XOR_MULT_DOSStub_20b3 {
  strings:
    $key_20b3 = { 74 db [2] 00 c3 [2] 47 c1 [2] 00 d0 [2] 4e dc [2] 42 d6 [2] 55 dd [2] 4e 93 [2] 73 }

  condition:
    any of them
}