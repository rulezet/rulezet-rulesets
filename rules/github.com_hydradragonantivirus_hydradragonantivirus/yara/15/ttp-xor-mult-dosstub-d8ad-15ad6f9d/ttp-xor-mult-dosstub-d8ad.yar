rule TTP_XOR_MULT_DOSStub_d8ad {
  strings:
    $key_d8ad = { 8c c5 [2] f8 dd [2] bf df [2] f8 ce [2] b6 c2 [2] ba c8 [2] ad c3 [2] b6 8d [2] 8b }

  condition:
    any of them
}