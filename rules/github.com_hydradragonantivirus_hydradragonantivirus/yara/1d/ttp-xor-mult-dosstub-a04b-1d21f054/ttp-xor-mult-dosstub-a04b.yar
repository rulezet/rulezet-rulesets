rule TTP_XOR_MULT_DOSStub_a04b {
  strings:
    $key_a04b = { f4 23 [2] 80 3b [2] c7 39 [2] 80 28 [2] ce 24 [2] c2 2e [2] d5 25 [2] ce 6b [2] f3 }

  condition:
    any of them
}