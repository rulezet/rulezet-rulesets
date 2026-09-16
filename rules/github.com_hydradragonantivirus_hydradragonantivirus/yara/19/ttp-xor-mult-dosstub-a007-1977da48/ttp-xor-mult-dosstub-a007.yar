rule TTP_XOR_MULT_DOSStub_a007 {
  strings:
    $key_a007 = { f4 6f [2] 80 77 [2] c7 75 [2] 80 64 [2] ce 68 [2] c2 62 [2] d5 69 [2] ce 27 [2] f3 }

  condition:
    any of them
}