rule TTP_XOR_MULT_DOSStub_35bd {
  strings:
    $key_35bd = { 61 d5 [2] 15 cd [2] 52 cf [2] 15 de [2] 5b d2 [2] 57 d8 [2] 40 d3 [2] 5b 9d [2] 66 }

  condition:
    any of them
}