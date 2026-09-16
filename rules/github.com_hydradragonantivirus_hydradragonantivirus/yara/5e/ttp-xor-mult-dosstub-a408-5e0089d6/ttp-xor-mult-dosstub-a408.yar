rule TTP_XOR_MULT_DOSStub_a408 {
  strings:
    $key_a408 = { f0 60 [2] 84 78 [2] c3 7a [2] 84 6b [2] ca 67 [2] c6 6d [2] d1 66 [2] ca 28 [2] f7 }

  condition:
    any of them
}