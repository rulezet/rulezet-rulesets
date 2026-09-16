rule TTP_XOR_MULT_DOSStub_a725 {
  strings:
    $key_a725 = { f3 4d [2] 87 55 [2] c0 57 [2] 87 46 [2] c9 4a [2] c5 40 [2] d2 4b [2] c9 05 [2] f4 }

  condition:
    any of them
}