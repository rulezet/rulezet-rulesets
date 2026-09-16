rule TTP_XOR_MULT_DOSStub_a004 {
  strings:
    $key_a004 = { f4 6c [2] 80 74 [2] c7 76 [2] 80 67 [2] ce 6b [2] c2 61 [2] d5 6a [2] ce 24 [2] f3 }

  condition:
    any of them
}