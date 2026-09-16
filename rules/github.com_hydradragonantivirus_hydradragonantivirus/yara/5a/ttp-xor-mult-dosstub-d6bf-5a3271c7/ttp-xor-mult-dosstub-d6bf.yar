rule TTP_XOR_MULT_DOSStub_d6bf {
  strings:
    $key_d6bf = { 82 d7 [2] f6 cf [2] b1 cd [2] f6 dc [2] b8 d0 [2] b4 da [2] a3 d1 [2] b8 9f [2] 85 }

  condition:
    any of them
}