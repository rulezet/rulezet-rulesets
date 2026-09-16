rule TTP_XOR_MULT_DOSStub_a135 {
  strings:
    $key_a135 = { f5 5d [2] 81 45 [2] c6 47 [2] 81 56 [2] cf 5a [2] c3 50 [2] d4 5b [2] cf 15 [2] f2 }

  condition:
    any of them
}