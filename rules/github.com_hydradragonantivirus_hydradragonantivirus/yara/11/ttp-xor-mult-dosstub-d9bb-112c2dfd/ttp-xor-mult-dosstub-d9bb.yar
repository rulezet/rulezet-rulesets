rule TTP_XOR_MULT_DOSStub_d9bb {
  strings:
    $key_d9bb = { 8d d3 [2] f9 cb [2] be c9 [2] f9 d8 [2] b7 d4 [2] bb de [2] ac d5 [2] b7 9b [2] 8a }

  condition:
    any of them
}