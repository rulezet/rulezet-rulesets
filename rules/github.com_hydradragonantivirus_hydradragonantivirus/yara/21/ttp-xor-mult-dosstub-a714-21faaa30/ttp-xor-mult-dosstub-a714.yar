rule TTP_XOR_MULT_DOSStub_a714 {
  strings:
    $key_a714 = { f3 7c [2] 87 64 [2] c0 66 [2] 87 77 [2] c9 7b [2] c5 71 [2] d2 7a [2] c9 34 [2] f4 }

  condition:
    any of them
}