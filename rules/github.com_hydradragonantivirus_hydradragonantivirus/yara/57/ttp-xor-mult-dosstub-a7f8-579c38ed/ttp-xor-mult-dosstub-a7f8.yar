rule TTP_XOR_MULT_DOSStub_a7f8 {
  strings:
    $key_a7f8 = { f3 90 [2] 87 88 [2] c0 8a [2] 87 9b [2] c9 97 [2] c5 9d [2] d2 96 [2] c9 d8 [2] f4 }

  condition:
    any of them
}