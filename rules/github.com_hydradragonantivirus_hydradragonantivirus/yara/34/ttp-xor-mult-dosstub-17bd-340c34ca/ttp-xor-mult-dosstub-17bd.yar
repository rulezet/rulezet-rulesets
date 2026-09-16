rule TTP_XOR_MULT_DOSStub_17bd {
  strings:
    $key_17bd = { 43 d5 [2] 37 cd [2] 70 cf [2] 37 de [2] 79 d2 [2] 75 d8 [2] 62 d3 [2] 79 9d [2] 44 }

  condition:
    any of them
}