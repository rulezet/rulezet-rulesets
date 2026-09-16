rule TTP_XOR_MULT_DOSStub_a014 {
  strings:
    $key_a014 = { f4 7c [2] 80 64 [2] c7 66 [2] 80 77 [2] ce 7b [2] c2 71 [2] d5 7a [2] ce 34 [2] f3 }

  condition:
    any of them
}