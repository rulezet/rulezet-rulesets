rule TTP_XOR_MULT_DOSStub_74b3 {
  strings:
    $key_74b3 = { 20 db [2] 54 c3 [2] 13 c1 [2] 54 d0 [2] 1a dc [2] 16 d6 [2] 01 dd [2] 1a 93 [2] 27 }

  condition:
    any of them
}