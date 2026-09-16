rule TTP_XOR_MULT_DOSStub_a762 {
  strings:
    $key_a762 = { f3 0a [2] 87 12 [2] c0 10 [2] 87 01 [2] c9 0d [2] c5 07 [2] d2 0c [2] c9 42 [2] f4 }

  condition:
    any of them
}