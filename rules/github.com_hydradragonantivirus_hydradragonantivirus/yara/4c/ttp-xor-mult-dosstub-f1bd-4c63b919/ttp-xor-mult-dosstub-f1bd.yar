rule TTP_XOR_MULT_DOSStub_f1bd {
  strings:
    $key_f1bd = { a5 d5 [2] d1 cd [2] 96 cf [2] d1 de [2] 9f d2 [2] 93 d8 [2] 84 d3 [2] 9f 9d [2] a2 }

  condition:
    any of them
}