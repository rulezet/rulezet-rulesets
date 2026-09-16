rule TTP_XOR_MULT_DOSStub_a001 {
  strings:
    $key_a001 = { f4 69 [2] 80 71 [2] c7 73 [2] 80 62 [2] ce 6e [2] c2 64 [2] d5 6f [2] ce 21 [2] f3 }

  condition:
    any of them
}