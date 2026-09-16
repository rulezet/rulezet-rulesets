rule TTP_XOR_MULT_DOSStub_a243 {
  strings:
    $key_a243 = { f6 2b [2] 82 33 [2] c5 31 [2] 82 20 [2] cc 2c [2] c0 26 [2] d7 2d [2] cc 63 [2] f1 }

  condition:
    any of them
}