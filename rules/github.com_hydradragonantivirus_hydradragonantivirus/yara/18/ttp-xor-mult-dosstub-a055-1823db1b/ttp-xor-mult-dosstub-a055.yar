rule TTP_XOR_MULT_DOSStub_a055 {
  strings:
    $key_a055 = { f4 3d [2] 80 25 [2] c7 27 [2] 80 36 [2] ce 3a [2] c2 30 [2] d5 3b [2] ce 75 [2] f3 }

  condition:
    any of them
}