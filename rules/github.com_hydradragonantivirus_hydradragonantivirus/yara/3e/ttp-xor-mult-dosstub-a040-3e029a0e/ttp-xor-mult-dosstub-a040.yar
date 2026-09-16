rule TTP_XOR_MULT_DOSStub_a040 {
  strings:
    $key_a040 = { f4 28 [2] 80 30 [2] c7 32 [2] 80 23 [2] ce 2f [2] c2 25 [2] d5 2e [2] ce 60 [2] f3 }

  condition:
    any of them
}