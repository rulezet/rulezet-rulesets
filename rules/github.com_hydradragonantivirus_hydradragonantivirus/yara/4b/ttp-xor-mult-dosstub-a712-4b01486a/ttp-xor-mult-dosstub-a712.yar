rule TTP_XOR_MULT_DOSStub_a712 {
  strings:
    $key_a712 = { f3 7a [2] 87 62 [2] c0 60 [2] 87 71 [2] c9 7d [2] c5 77 [2] d2 7c [2] c9 32 [2] f4 }

  condition:
    any of them
}