rule TTP_XOR_MULT_DOSStub_87bd {
  strings:
    $key_87bd = { d3 d5 [2] a7 cd [2] e0 cf [2] a7 de [2] e9 d2 [2] e5 d8 [2] f2 d3 [2] e9 9d [2] d4 }

  condition:
    any of them
}