rule TTP_XOR_MULT_DOSStub_86bd {
  strings:
    $key_86bd = { d2 d5 [2] a6 cd [2] e1 cf [2] a6 de [2] e8 d2 [2] e4 d8 [2] f3 d3 [2] e8 9d [2] d5 }

  condition:
    any of them
}