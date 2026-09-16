rule TTP_XOR_MULT_DOSStub_5fbd {
  strings:
    $key_5fbd = { 0b d5 [2] 7f cd [2] 38 cf [2] 7f de [2] 31 d2 [2] 3d d8 [2] 2a d3 [2] 31 9d [2] 0c }

  condition:
    any of them
}