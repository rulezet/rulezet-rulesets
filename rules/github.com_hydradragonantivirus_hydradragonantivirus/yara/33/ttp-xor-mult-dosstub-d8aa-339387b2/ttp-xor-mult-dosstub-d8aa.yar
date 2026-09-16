rule TTP_XOR_MULT_DOSStub_d8aa {
  strings:
    $key_d8aa = { 8c c2 [2] f8 da [2] bf d8 [2] f8 c9 [2] b6 c5 [2] ba cf [2] ad c4 [2] b6 8a [2] 8b }

  condition:
    any of them
}