rule TTP_XOR_MULT_DOSStub_28bd {
  strings:
    $key_28bd = { 7c d5 [2] 08 cd [2] 4f cf [2] 08 de [2] 46 d2 [2] 4a d8 [2] 5d d3 [2] 46 9d [2] 7b }

  condition:
    any of them
}