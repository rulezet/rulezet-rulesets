rule TTP_XOR_MULT_DOSStub_a1a9 {
  strings:
    $key_a1a9 = { f5 c1 [2] 81 d9 [2] c6 db [2] 81 ca [2] cf c6 [2] c3 cc [2] d4 c7 [2] cf 89 [2] f2 }

  condition:
    any of them
}