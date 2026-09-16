rule TTP_XOR_MULT_DOSStub_a763 {
  strings:
    $key_a763 = { f3 0b [2] 87 13 [2] c0 11 [2] 87 00 [2] c9 0c [2] c5 06 [2] d2 0d [2] c9 43 [2] f4 }

  condition:
    any of them
}