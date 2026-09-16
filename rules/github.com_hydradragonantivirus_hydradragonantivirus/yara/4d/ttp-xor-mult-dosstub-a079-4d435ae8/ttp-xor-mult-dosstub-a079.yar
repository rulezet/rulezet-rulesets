rule TTP_XOR_MULT_DOSStub_a079 {
  strings:
    $key_a079 = { f4 11 [2] 80 09 [2] c7 0b [2] 80 1a [2] ce 16 [2] c2 1c [2] d5 17 [2] ce 59 [2] f3 }

  condition:
    any of them
}