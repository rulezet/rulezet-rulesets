rule TTP_XOR_MULT_DOSStub_07bd {
  strings:
    $key_07bd = { 53 d5 [2] 27 cd [2] 60 cf [2] 27 de [2] 69 d2 [2] 65 d8 [2] 72 d3 [2] 69 9d [2] 54 }

  condition:
    any of them
}