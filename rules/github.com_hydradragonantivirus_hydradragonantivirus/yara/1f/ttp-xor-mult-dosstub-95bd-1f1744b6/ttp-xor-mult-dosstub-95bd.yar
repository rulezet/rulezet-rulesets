rule TTP_XOR_MULT_DOSStub_95bd {
  strings:
    $key_95bd = { c1 d5 [2] b5 cd [2] f2 cf [2] b5 de [2] fb d2 [2] f7 d8 [2] e0 d3 [2] fb 9d [2] c6 }

  condition:
    any of them
}