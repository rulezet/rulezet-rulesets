rule TTP_XOR_MULT_DOSStub_a728 {
  strings:
    $key_a728 = { f3 40 [2] 87 58 [2] c0 5a [2] 87 4b [2] c9 47 [2] c5 4d [2] d2 46 [2] c9 08 [2] f4 }

  condition:
    any of them
}