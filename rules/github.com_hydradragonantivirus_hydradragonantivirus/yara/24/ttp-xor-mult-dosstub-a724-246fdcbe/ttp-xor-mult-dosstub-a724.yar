rule TTP_XOR_MULT_DOSStub_a724 {
  strings:
    $key_a724 = { f3 4c [2] 87 54 [2] c0 56 [2] 87 47 [2] c9 4b [2] c5 41 [2] d2 4a [2] c9 04 [2] f4 }

  condition:
    any of them
}