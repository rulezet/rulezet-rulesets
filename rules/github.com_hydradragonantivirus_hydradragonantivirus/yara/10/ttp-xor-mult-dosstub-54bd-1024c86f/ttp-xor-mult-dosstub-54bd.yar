rule TTP_XOR_MULT_DOSStub_54bd {
  strings:
    $key_54bd = { 00 d5 [2] 74 cd [2] 33 cf [2] 74 de [2] 3a d2 [2] 36 d8 [2] 21 d3 [2] 3a 9d [2] 07 }

  condition:
    any of them
}