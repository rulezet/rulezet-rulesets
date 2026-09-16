rule TTP_XOR_MULT_DOSStub_49bd {
  strings:
    $key_49bd = { 1d d5 [2] 69 cd [2] 2e cf [2] 69 de [2] 27 d2 [2] 2b d8 [2] 3c d3 [2] 27 9d [2] 1a }

  condition:
    any of them
}