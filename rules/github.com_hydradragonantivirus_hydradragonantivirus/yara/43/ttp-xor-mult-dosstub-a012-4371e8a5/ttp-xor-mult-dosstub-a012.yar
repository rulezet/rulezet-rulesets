rule TTP_XOR_MULT_DOSStub_a012 {
  strings:
    $key_a012 = { f4 7a [2] 80 62 [2] c7 60 [2] 80 71 [2] ce 7d [2] c2 77 [2] d5 7c [2] ce 32 [2] f3 }

  condition:
    any of them
}