rule TTP_XOR_MULT_DOSStub_a046 {
  strings:
    $key_a046 = { f4 2e [2] 80 36 [2] c7 34 [2] 80 25 [2] ce 29 [2] c2 23 [2] d5 28 [2] ce 66 [2] f3 }

  condition:
    any of them
}