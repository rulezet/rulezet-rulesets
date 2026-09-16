rule TTP_XOR_MULT_DOSStub_92bd {
  strings:
    $key_92bd = { c6 d5 [2] b2 cd [2] f5 cf [2] b2 de [2] fc d2 [2] f0 d8 [2] e7 d3 [2] fc 9d [2] c1 }

  condition:
    any of them
}