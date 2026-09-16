rule TTP_XOR_MULT_DOSStub_a0e6 {
  strings:
    $key_a0e6 = { f4 8e [2] 80 96 [2] c7 94 [2] 80 85 [2] ce 89 [2] c2 83 [2] d5 88 [2] ce c6 [2] f3 }

  condition:
    any of them
}