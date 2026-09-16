rule TTP_XOR_MULT_DOSStub_82bd {
  strings:
    $key_82bd = { d6 d5 [2] a2 cd [2] e5 cf [2] a2 de [2] ec d2 [2] e0 d8 [2] f7 d3 [2] ec 9d [2] d1 }

  condition:
    any of them
}