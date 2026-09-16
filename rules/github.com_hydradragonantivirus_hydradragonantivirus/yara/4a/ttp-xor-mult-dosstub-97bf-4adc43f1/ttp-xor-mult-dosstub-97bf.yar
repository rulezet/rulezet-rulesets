rule TTP_XOR_MULT_DOSStub_97bf {
  strings:
    $key_97bf = { c3 d7 [2] b7 cf [2] f0 cd [2] b7 dc [2] f9 d0 [2] f5 da [2] e2 d1 [2] f9 9f [2] c4 }

  condition:
    any of them
}