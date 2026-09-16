rule TTP_XOR_MULT_DOSStub_70bd {
  strings:
    $key_70bd = { 24 d5 [2] 50 cd [2] 17 cf [2] 50 de [2] 1e d2 [2] 12 d8 [2] 05 d3 [2] 1e 9d [2] 23 }

  condition:
    any of them
}