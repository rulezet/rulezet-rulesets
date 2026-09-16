rule TTP_XOR_MULT_DOSStub_23bd {
  strings:
    $key_23bd = { 77 d5 [2] 03 cd [2] 44 cf [2] 03 de [2] 4d d2 [2] 41 d8 [2] 56 d3 [2] 4d 9d [2] 70 }

  condition:
    any of them
}