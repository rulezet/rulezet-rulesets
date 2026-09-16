rule TTP_XOR_MULT_DOSStub_a404 {
  strings:
    $key_a404 = { f0 6c [2] 84 74 [2] c3 76 [2] 84 67 [2] ca 6b [2] c6 61 [2] d1 6a [2] ca 24 [2] f7 }

  condition:
    any of them
}