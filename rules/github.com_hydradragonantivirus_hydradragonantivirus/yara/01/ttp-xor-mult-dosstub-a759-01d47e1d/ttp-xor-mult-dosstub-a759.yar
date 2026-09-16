rule TTP_XOR_MULT_DOSStub_a759 {
  strings:
    $key_a759 = { f3 31 [2] 87 29 [2] c0 2b [2] 87 3a [2] c9 36 [2] c5 3c [2] d2 37 [2] c9 79 [2] f4 }

  condition:
    any of them
}