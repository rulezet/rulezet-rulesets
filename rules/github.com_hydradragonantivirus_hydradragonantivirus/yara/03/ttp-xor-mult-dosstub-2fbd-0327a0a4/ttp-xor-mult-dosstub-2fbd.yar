rule TTP_XOR_MULT_DOSStub_2fbd {
  strings:
    $key_2fbd = { 7b d5 [2] 0f cd [2] 48 cf [2] 0f de [2] 41 d2 [2] 4d d8 [2] 5a d3 [2] 41 9d [2] 7c }

  condition:
    any of them
}