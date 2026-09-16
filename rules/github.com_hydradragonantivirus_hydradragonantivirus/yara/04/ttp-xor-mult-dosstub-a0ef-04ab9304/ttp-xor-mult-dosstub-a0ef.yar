rule TTP_XOR_MULT_DOSStub_a0ef {
  strings:
    $key_a0ef = { f4 87 [2] 80 9f [2] c7 9d [2] 80 8c [2] ce 80 [2] c2 8a [2] d5 81 [2] ce cf [2] f3 }

  condition:
    any of them
}