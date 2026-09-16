rule TTP_XOR_MULT_DOSStub_f4bd {
  strings:
    $key_f4bd = { a0 d5 [2] d4 cd [2] 93 cf [2] d4 de [2] 9a d2 [2] 96 d8 [2] 81 d3 [2] 9a 9d [2] a7 }

  condition:
    any of them
}