rule TTP_XOR_MULT_DOSStub_a097 {
  strings:
    $key_a097 = { f4 ff [2] 80 e7 [2] c7 e5 [2] 80 f4 [2] ce f8 [2] c2 f2 [2] d5 f9 [2] ce b7 [2] f3 }

  condition:
    any of them
}