rule TTP_XOR_MULT_DOSStub_21bd {
  strings:
    $key_21bd = { 75 d5 [2] 01 cd [2] 46 cf [2] 01 de [2] 4f d2 [2] 43 d8 [2] 54 d3 [2] 4f 9d [2] 72 }

  condition:
    any of them
}