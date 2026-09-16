rule TTP_XOR_MULT_DOSStub_d8a3 {
  strings:
    $key_d8a3 = { 8c cb [2] f8 d3 [2] bf d1 [2] f8 c0 [2] b6 cc [2] ba c6 [2] ad cd [2] b6 83 [2] 8b }

  condition:
    any of them
}