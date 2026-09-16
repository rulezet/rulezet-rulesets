rule TTP_XOR_MULT_DOSStub_a050 {
  strings:
    $key_a050 = { f4 38 [2] 80 20 [2] c7 22 [2] 80 33 [2] ce 3f [2] c2 35 [2] d5 3e [2] ce 70 [2] f3 }

  condition:
    any of them
}