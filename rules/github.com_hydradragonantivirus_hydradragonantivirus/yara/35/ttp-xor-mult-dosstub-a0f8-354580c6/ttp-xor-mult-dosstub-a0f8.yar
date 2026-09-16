rule TTP_XOR_MULT_DOSStub_a0f8 {
  strings:
    $key_a0f8 = { f4 90 [2] 80 88 [2] c7 8a [2] 80 9b [2] ce 97 [2] c2 9d [2] d5 96 [2] ce d8 [2] f3 }

  condition:
    any of them
}