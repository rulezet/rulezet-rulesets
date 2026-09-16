rule TTP_XOR_MULT_DOSStub_a005 {
  strings:
    $key_a005 = { f4 6d [2] 80 75 [2] c7 77 [2] 80 66 [2] ce 6a [2] c2 60 [2] d5 6b [2] ce 25 [2] f3 }

  condition:
    any of them
}