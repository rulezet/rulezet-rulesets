rule TTP_XOR_MULT_DOSStub_d8bd {
  strings:
    $key_d8bd = { 8c d5 [2] f8 cd [2] bf cf [2] f8 de [2] b6 d2 [2] ba d8 [2] ad d3 [2] b6 9d [2] 8b }

  condition:
    any of them
}