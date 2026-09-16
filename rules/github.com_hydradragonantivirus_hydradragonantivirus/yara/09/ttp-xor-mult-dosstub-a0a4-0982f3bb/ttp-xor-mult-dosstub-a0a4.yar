rule TTP_XOR_MULT_DOSStub_a0a4 {
  strings:
    $key_a0a4 = { f4 cc [2] 80 d4 [2] c7 d6 [2] 80 c7 [2] ce cb [2] c2 c1 [2] d5 ca [2] ce 84 [2] f3 }

  condition:
    any of them
}