rule TTP_XOR_MULT_DOSStub_a718 {
  strings:
    $key_a718 = { f3 70 [2] 87 68 [2] c0 6a [2] 87 7b [2] c9 77 [2] c5 7d [2] d2 76 [2] c9 38 [2] f4 }

  condition:
    any of them
}