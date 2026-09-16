rule TTP_XOR_MULT_DOSStub_a0e2 {
  strings:
    $key_a0e2 = { f4 8a [2] 80 92 [2] c7 90 [2] 80 81 [2] ce 8d [2] c2 87 [2] d5 8c [2] ce c2 [2] f3 }

  condition:
    any of them
}