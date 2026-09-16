rule TTP_XOR_MULT_DOSStub_a415 {
  strings:
    $key_a415 = { f0 7d [2] 84 65 [2] c3 67 [2] 84 76 [2] ca 7a [2] c6 70 [2] d1 7b [2] ca 35 [2] f7 }

  condition:
    any of them
}