rule TTP_XOR_MULT_DOSStub_22bd {
  strings:
    $key_22bd = { 76 d5 [2] 02 cd [2] 45 cf [2] 02 de [2] 4c d2 [2] 40 d8 [2] 57 d3 [2] 4c 9d [2] 71 }

  condition:
    any of them
}