rule TTP_XOR_MULT_DOSStub_4fbd {
  strings:
    $key_4fbd = { 1b d5 [2] 6f cd [2] 28 cf [2] 6f de [2] 21 d2 [2] 2d d8 [2] 3a d3 [2] 21 9d [2] 1c }

  condition:
    any of them
}