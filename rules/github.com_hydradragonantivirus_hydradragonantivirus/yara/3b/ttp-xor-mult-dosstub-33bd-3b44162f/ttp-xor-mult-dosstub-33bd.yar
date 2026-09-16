rule TTP_XOR_MULT_DOSStub_33bd {
  strings:
    $key_33bd = { 67 d5 [2] 13 cd [2] 54 cf [2] 13 de [2] 5d d2 [2] 51 d8 [2] 46 d3 [2] 5d 9d [2] 60 }

  condition:
    any of them
}