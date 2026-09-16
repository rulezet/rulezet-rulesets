rule TTP_XOR_MULT_DOSStub_d1bf {
  strings:
    $key_d1bf = { 85 d7 [2] f1 cf [2] b6 cd [2] f1 dc [2] bf d0 [2] b3 da [2] a4 d1 [2] bf 9f [2] 82 }

  condition:
    any of them
}