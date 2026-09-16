rule TTP_XOR_MULT_DOSStub_26bd {
  strings:
    $key_26bd = { 72 d5 [2] 06 cd [2] 41 cf [2] 06 de [2] 48 d2 [2] 44 d8 [2] 53 d3 [2] 48 9d [2] 75 }

  condition:
    any of them
}