rule TTP_XOR_MULT_DOSStub_50bd {
  strings:
    $key_50bd = { 04 d5 [2] 70 cd [2] 37 cf [2] 70 de [2] 3e d2 [2] 32 d8 [2] 25 d3 [2] 3e 9d [2] 03 }

  condition:
    any of them
}