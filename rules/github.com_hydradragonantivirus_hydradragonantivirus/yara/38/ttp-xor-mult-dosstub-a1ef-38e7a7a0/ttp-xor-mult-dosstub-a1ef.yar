rule TTP_XOR_MULT_DOSStub_a1ef {
  strings:
    $key_a1ef = { f5 87 [2] 81 9f [2] c6 9d [2] 81 8c [2] cf 80 [2] c3 8a [2] d4 81 [2] cf cf [2] f2 }

  condition:
    any of them
}