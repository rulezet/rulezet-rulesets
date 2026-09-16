rule TTP_XOR_MULT_DOSStub_a0f7 {
  strings:
    $key_a0f7 = { f4 9f [2] 80 87 [2] c7 85 [2] 80 94 [2] ce 98 [2] c2 92 [2] d5 99 [2] ce d7 [2] f3 }

  condition:
    any of them
}