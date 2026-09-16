rule TTP_XOR_MULT_DOSStub_a4ef {
  strings:
    $key_a4ef = { f0 87 [2] 84 9f [2] c3 9d [2] 84 8c [2] ca 80 [2] c6 8a [2] d1 81 [2] ca cf [2] f7 }

  condition:
    any of them
}