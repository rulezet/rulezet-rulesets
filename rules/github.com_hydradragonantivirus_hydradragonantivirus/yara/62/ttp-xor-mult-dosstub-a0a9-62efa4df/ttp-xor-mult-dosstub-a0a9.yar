rule TTP_XOR_MULT_DOSStub_a0a9 {
  strings:
    $key_a0a9 = { f4 c1 [2] 80 d9 [2] c7 db [2] 80 ca [2] ce c6 [2] c2 cc [2] d5 c7 [2] ce 89 [2] f3 }

  condition:
    any of them
}