rule TTP_XOR_MULT_DOSStub_d1bd {
  strings:
    $key_d1bd = { 85 d5 [2] f1 cd [2] b6 cf [2] f1 de [2] bf d2 [2] b3 d8 [2] a4 d3 [2] bf 9d [2] 82 }

  condition:
    any of them
}