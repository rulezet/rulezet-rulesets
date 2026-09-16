rule TTP_XOR_MULT_DOSStub_e8bd {
  strings:
    $key_e8bd = { bc d5 [2] c8 cd [2] 8f cf [2] c8 de [2] 86 d2 [2] 8a d8 [2] 9d d3 [2] 86 9d [2] bb }

  condition:
    any of them
}