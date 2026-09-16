rule TTP_XOR_MULT_DOSStub_a044 {
  strings:
    $key_a044 = { f4 2c [2] 80 34 [2] c7 36 [2] 80 27 [2] ce 2b [2] c2 21 [2] d5 2a [2] ce 64 [2] f3 }

  condition:
    any of them
}