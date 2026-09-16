rule TTP_XOR_MULT_DOSStub_7abd {
  strings:
    $key_7abd = { 2e d5 [2] 5a cd [2] 1d cf [2] 5a de [2] 14 d2 [2] 18 d8 [2] 0f d3 [2] 14 9d [2] 29 }

  condition:
    any of them
}