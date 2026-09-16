rule TTP_XOR_MULT_DOSStub_a0e8 {
  strings:
    $key_a0e8 = { f4 80 [2] 80 98 [2] c7 9a [2] 80 8b [2] ce 87 [2] c2 8d [2] d5 86 [2] ce c8 [2] f3 }

  condition:
    any of them
}