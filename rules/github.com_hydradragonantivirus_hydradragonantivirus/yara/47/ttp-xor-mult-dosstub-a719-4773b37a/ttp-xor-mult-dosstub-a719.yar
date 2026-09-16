rule TTP_XOR_MULT_DOSStub_a719 {
  strings:
    $key_a719 = { f3 71 [2] 87 69 [2] c0 6b [2] 87 7a [2] c9 76 [2] c5 7c [2] d2 77 [2] c9 39 [2] f4 }

  condition:
    any of them
}