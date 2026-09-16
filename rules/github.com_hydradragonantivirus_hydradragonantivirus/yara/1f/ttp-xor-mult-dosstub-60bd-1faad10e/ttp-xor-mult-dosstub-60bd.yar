rule TTP_XOR_MULT_DOSStub_60bd {
  strings:
    $key_60bd = { 34 d5 [2] 40 cd [2] 07 cf [2] 40 de [2] 0e d2 [2] 02 d8 [2] 15 d3 [2] 0e 9d [2] 33 }

  condition:
    any of them
}