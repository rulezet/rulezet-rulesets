rule TTP_XOR_MULT_DOSStub_54b3 {
  strings:
    $key_54b3 = { 00 db [2] 74 c3 [2] 33 c1 [2] 74 d0 [2] 3a dc [2] 36 d6 [2] 21 dd [2] 3a 93 [2] 07 }

  condition:
    any of them
}