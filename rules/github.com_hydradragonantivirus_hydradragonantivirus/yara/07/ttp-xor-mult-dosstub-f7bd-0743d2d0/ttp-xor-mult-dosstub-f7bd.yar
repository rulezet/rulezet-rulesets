rule TTP_XOR_MULT_DOSStub_f7bd {
  strings:
    $key_f7bd = { a3 d5 [2] d7 cd [2] 90 cf [2] d7 de [2] 99 d2 [2] 95 d8 [2] 82 d3 [2] 99 9d [2] a4 }

  condition:
    any of them
}