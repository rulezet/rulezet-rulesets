rule TTP_XOR_MULT_DOSStub_a739 {
  strings:
    $key_a739 = { f3 51 [2] 87 49 [2] c0 4b [2] 87 5a [2] c9 56 [2] c5 5c [2] d2 57 [2] c9 19 [2] f4 }

  condition:
    any of them
}