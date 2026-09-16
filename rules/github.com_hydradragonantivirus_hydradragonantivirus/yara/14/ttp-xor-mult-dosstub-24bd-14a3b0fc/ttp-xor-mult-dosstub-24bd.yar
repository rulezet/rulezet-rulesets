rule TTP_XOR_MULT_DOSStub_24bd {
  strings:
    $key_24bd = { 70 d5 [2] 04 cd [2] 43 cf [2] 04 de [2] 4a d2 [2] 46 d8 [2] 51 d3 [2] 4a 9d [2] 77 }

  condition:
    any of them
}