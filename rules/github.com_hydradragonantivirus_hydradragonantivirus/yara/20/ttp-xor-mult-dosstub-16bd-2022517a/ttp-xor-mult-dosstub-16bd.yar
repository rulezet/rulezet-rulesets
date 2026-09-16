rule TTP_XOR_MULT_DOSStub_16bd {
  strings:
    $key_16bd = { 42 d5 [2] 36 cd [2] 71 cf [2] 36 de [2] 78 d2 [2] 74 d8 [2] 63 d3 [2] 78 9d [2] 45 }

  condition:
    any of them
}