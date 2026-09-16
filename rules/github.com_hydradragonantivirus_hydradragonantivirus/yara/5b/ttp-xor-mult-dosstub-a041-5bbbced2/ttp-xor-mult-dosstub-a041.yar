rule TTP_XOR_MULT_DOSStub_a041 {
  strings:
    $key_a041 = { f4 29 [2] 80 31 [2] c7 33 [2] 80 22 [2] ce 2e [2] c2 24 [2] d5 2f [2] ce 61 [2] f3 }

  condition:
    any of them
}