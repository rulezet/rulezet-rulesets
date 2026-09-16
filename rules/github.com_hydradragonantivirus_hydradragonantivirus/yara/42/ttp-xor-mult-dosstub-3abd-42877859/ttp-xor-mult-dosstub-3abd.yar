rule TTP_XOR_MULT_DOSStub_3abd {
  strings:
    $key_3abd = { 6e d5 [2] 1a cd [2] 5d cf [2] 1a de [2] 54 d2 [2] 58 d8 [2] 4f d3 [2] 54 9d [2] 69 }

  condition:
    any of them
}