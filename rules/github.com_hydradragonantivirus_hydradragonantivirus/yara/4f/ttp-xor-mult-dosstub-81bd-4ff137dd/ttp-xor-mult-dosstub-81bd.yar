rule TTP_XOR_MULT_DOSStub_81bd {
  strings:
    $key_81bd = { d5 d5 [2] a1 cd [2] e6 cf [2] a1 de [2] ef d2 [2] e3 d8 [2] f4 d3 [2] ef 9d [2] d2 }

  condition:
    any of them
}