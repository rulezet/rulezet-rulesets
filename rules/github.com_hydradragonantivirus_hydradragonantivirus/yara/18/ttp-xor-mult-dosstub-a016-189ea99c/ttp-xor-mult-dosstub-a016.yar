rule TTP_XOR_MULT_DOSStub_a016 {
  strings:
    $key_a016 = { f4 7e [2] 80 66 [2] c7 64 [2] 80 75 [2] ce 79 [2] c2 73 [2] d5 78 [2] ce 36 [2] f3 }

  condition:
    any of them
}