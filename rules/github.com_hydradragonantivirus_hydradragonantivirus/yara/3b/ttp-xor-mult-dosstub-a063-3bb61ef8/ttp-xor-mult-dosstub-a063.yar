rule TTP_XOR_MULT_DOSStub_a063 {
  strings:
    $key_a063 = { f4 0b [2] 80 13 [2] c7 11 [2] 80 00 [2] ce 0c [2] c2 06 [2] d5 0d [2] ce 43 [2] f3 }

  condition:
    any of them
}