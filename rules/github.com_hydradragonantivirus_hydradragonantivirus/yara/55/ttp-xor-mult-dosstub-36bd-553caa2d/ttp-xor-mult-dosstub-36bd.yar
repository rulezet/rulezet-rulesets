rule TTP_XOR_MULT_DOSStub_36bd {
  strings:
    $key_36bd = { 62 d5 [2] 16 cd [2] 51 cf [2] 16 de [2] 58 d2 [2] 54 d8 [2] 43 d3 [2] 58 9d [2] 65 }

  condition:
    any of them
}