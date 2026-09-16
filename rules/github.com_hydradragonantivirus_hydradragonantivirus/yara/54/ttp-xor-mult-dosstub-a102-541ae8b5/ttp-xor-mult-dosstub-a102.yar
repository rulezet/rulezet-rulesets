rule TTP_XOR_MULT_DOSStub_a102 {
  strings:
    $key_a102 = { f5 6a [2] 81 72 [2] c6 70 [2] 81 61 [2] cf 6d [2] c3 67 [2] d4 6c [2] cf 22 [2] f2 }

  condition:
    any of them
}