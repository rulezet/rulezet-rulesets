rule TTP_XOR_MULT_DOSStub_b4bd {
  strings:
    $key_b4bd = { e0 d5 [2] 94 cd [2] d3 cf [2] 94 de [2] da d2 [2] d6 d8 [2] c1 d3 [2] da 9d [2] e7 }

  condition:
    any of them
}