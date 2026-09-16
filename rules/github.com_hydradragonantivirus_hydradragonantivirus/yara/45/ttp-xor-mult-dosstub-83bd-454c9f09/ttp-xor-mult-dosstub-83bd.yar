rule TTP_XOR_MULT_DOSStub_83bd {
  strings:
    $key_83bd = { d7 d5 [2] a3 cd [2] e4 cf [2] a3 de [2] ed d2 [2] e1 d8 [2] f6 d3 [2] ed 9d [2] d0 }

  condition:
    any of them
}