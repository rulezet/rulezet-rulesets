rule TTP_XOR_MULT_DOSStub_d8a4 {
  strings:
    $key_d8a4 = { 8c cc [2] f8 d4 [2] bf d6 [2] f8 c7 [2] b6 cb [2] ba c1 [2] ad ca [2] b6 84 [2] 8b }

  condition:
    any of them
}