rule TTP_XOR_MULT_DOSStub_38bd {
  strings:
    $key_38bd = { 6c d5 [2] 18 cd [2] 5f cf [2] 18 de [2] 56 d2 [2] 5a d8 [2] 4d d3 [2] 56 9d [2] 6b }

  condition:
    any of them
}