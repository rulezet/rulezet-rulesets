rule TTP_XOR_MULT_DOSStub_a049 {
  strings:
    $key_a049 = { f4 21 [2] 80 39 [2] c7 3b [2] 80 2a [2] ce 26 [2] c2 2c [2] d5 27 [2] ce 69 [2] f3 }

  condition:
    any of them
}