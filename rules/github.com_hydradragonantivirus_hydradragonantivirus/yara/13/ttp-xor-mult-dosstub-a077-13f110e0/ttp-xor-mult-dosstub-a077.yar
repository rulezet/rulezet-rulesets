rule TTP_XOR_MULT_DOSStub_a077 {
  strings:
    $key_a077 = { f4 1f [2] 80 07 [2] c7 05 [2] 80 14 [2] ce 18 [2] c2 12 [2] d5 19 [2] ce 57 [2] f3 }

  condition:
    any of them
}