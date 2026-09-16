rule TTP_XOR_MULT_DOSStub_e0bd {
  strings:
    $key_e0bd = { b4 d5 [2] c0 cd [2] 87 cf [2] c0 de [2] 8e d2 [2] 82 d8 [2] 95 d3 [2] 8e 9d [2] b3 }

  condition:
    any of them
}