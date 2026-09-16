rule TTP_XOR_MULT_DOSStub_a017 {
  strings:
    $key_a017 = { f4 7f [2] 80 67 [2] c7 65 [2] 80 74 [2] ce 78 [2] c2 72 [2] d5 79 [2] ce 37 [2] f3 }

  condition:
    any of them
}