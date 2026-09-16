rule TTP_XOR_MULT_DOSStub_90bb {
  strings:
    $key_90bb = { c4 d3 [2] b0 cb [2] f7 c9 [2] b0 d8 [2] fe d4 [2] f2 de [2] e5 d5 [2] fe 9b [2] c3 }

  condition:
    any of them
}