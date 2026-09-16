rule TTP_XOR_MULT_DOSStub_b3bd {
  strings:
    $key_b3bd = { e7 d5 [2] 93 cd [2] d4 cf [2] 93 de [2] dd d2 [2] d1 d8 [2] c6 d3 [2] dd 9d [2] e0 }

  condition:
    any of them
}