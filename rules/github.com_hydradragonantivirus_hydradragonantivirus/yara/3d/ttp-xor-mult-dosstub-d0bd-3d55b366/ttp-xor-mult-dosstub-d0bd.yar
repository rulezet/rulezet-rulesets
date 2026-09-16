rule TTP_XOR_MULT_DOSStub_d0bd {
  strings:
    $key_d0bd = { 84 d5 [2] f0 cd [2] b7 cf [2] f0 de [2] be d2 [2] b2 d8 [2] a5 d3 [2] be 9d [2] 83 }

  condition:
    any of them
}