rule TTP_XOR_MULT_DOSStub_94bd {
  strings:
    $key_94bd = { c0 d5 [2] b4 cd [2] f3 cf [2] b4 de [2] fa d2 [2] f6 d8 [2] e1 d3 [2] fa 9d [2] c7 }

  condition:
    any of them
}