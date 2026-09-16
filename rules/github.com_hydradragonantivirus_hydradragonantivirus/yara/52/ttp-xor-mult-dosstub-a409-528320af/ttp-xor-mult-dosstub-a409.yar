rule TTP_XOR_MULT_DOSStub_a409 {
  strings:
    $key_a409 = { f0 61 [2] 84 79 [2] c3 7b [2] 84 6a [2] ca 66 [2] c6 6c [2] d1 67 [2] ca 29 [2] f7 }

  condition:
    any of them
}