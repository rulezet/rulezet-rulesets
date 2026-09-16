rule TTP_XOR_MULT_DOSStub_58bd {
  strings:
    $key_58bd = { 0c d5 [2] 78 cd [2] 3f cf [2] 78 de [2] 36 d2 [2] 3a d8 [2] 2d d3 [2] 36 9d [2] 0b }

  condition:
    any of them
}