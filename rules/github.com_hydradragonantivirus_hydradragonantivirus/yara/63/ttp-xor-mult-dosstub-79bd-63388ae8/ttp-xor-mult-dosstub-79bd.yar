rule TTP_XOR_MULT_DOSStub_79bd {
  strings:
    $key_79bd = { 2d d5 [2] 59 cd [2] 1e cf [2] 59 de [2] 17 d2 [2] 1b d8 [2] 0c d3 [2] 17 9d [2] 2a }

  condition:
    any of them
}