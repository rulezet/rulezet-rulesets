rule TTP_XOR_MULT_DOSStub_1abd {
  strings:
    $key_1abd = { 4e d5 [2] 3a cd [2] 7d cf [2] 3a de [2] 74 d2 [2] 78 d8 [2] 6f d3 [2] 74 9d [2] 49 }

  condition:
    any of them
}