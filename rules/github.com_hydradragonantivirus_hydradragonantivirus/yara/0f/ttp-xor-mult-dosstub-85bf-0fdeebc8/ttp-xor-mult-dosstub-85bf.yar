rule TTP_XOR_MULT_DOSStub_85bf {
  strings:
    $key_85bf = { d1 d7 [2] a5 cf [2] e2 cd [2] a5 dc [2] eb d0 [2] e7 da [2] f0 d1 [2] eb 9f [2] d6 }

  condition:
    any of them
}