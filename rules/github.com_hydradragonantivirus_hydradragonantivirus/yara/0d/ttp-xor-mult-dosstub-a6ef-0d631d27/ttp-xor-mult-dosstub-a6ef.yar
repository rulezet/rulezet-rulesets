rule TTP_XOR_MULT_DOSStub_a6ef {
  strings:
    $key_a6ef = { f2 87 [2] 86 9f [2] c1 9d [2] 86 8c [2] c8 80 [2] c4 8a [2] d3 81 [2] c8 cf [2] f5 }

  condition:
    any of them
}