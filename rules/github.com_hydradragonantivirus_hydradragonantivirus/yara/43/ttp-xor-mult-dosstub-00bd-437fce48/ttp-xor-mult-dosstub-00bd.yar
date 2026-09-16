rule TTP_XOR_MULT_DOSStub_00bd {
  strings:
    $key_00bd = { 54 d5 [2] 20 cd [2] 67 cf [2] 20 de [2] 6e d2 [2] 62 d8 [2] 75 d3 [2] 6e 9d [2] 53 }

  condition:
    any of them
}