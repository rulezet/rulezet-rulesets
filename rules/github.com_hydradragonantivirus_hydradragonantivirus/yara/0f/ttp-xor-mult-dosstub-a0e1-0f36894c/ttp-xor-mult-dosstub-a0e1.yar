rule TTP_XOR_MULT_DOSStub_a0e1 {
  strings:
    $key_a0e1 = { f4 89 [2] 80 91 [2] c7 93 [2] 80 82 [2] ce 8e [2] c2 84 [2] d5 8f [2] ce c1 [2] f3 }

  condition:
    any of them
}