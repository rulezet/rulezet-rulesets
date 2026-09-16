rule TTP_XOR_MULT_DOSStub_a702 {
  strings:
    $key_a702 = { f3 6a [2] 87 72 [2] c0 70 [2] 87 61 [2] c9 6d [2] c5 67 [2] d2 6c [2] c9 22 [2] f4 }

  condition:
    any of them
}