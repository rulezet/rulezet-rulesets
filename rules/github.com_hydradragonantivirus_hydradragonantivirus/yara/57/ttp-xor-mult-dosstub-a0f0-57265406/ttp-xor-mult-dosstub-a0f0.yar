rule TTP_XOR_MULT_DOSStub_a0f0 {
  strings:
    $key_a0f0 = { f4 98 [2] 80 80 [2] c7 82 [2] 80 93 [2] ce 9f [2] c2 95 [2] d5 9e [2] ce d0 [2] f3 }

  condition:
    any of them
}