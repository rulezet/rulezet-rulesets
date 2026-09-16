rule TTP_XOR_MULT_DOSStub_d6bd {
  strings:
    $key_d6bd = { 82 d5 [2] f6 cd [2] b1 cf [2] f6 de [2] b8 d2 [2] b4 d8 [2] a3 d3 [2] b8 9d [2] 85 }

  condition:
    any of them
}