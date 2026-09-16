rule TTP_XOR_MULT_DOSStub_d9b6 {
  strings:
    $key_d9b6 = { 8d de [2] f9 c6 [2] be c4 [2] f9 d5 [2] b7 d9 [2] bb d3 [2] ac d8 [2] b7 96 [2] 8a }

  condition:
    any of them
}