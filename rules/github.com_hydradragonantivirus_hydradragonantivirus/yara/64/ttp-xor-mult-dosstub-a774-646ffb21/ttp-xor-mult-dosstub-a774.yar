rule TTP_XOR_MULT_DOSStub_a774 {
  strings:
    $key_a774 = { f3 1c [2] 87 04 [2] c0 06 [2] 87 17 [2] c9 1b [2] c5 11 [2] d2 1a [2] c9 54 [2] f4 }

  condition:
    any of them
}