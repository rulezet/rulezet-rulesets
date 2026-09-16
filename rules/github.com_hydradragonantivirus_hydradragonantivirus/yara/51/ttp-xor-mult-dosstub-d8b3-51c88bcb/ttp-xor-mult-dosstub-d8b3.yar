rule TTP_XOR_MULT_DOSStub_d8b3 {
  strings:
    $key_d8b3 = { 8c db [2] f8 c3 [2] bf c1 [2] f8 d0 [2] b6 dc [2] ba d6 [2] ad dd [2] b6 93 [2] 8b }

  condition:
    any of them
}