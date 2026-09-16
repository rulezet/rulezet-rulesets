rule TTP_XOR_MULT_DOSStub_a076 {
  strings:
    $key_a076 = { f4 1e [2] 80 06 [2] c7 04 [2] 80 15 [2] ce 19 [2] c2 13 [2] d5 18 [2] ce 56 [2] f3 }

  condition:
    any of them
}