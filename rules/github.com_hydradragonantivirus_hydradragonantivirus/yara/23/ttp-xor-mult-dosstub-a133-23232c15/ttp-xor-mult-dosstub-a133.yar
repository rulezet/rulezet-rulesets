rule TTP_XOR_MULT_DOSStub_a133 {
  strings:
    $key_a133 = { f5 5b [2] 81 43 [2] c6 41 [2] 81 50 [2] cf 5c [2] c3 56 [2] d4 5d [2] cf 13 [2] f2 }

  condition:
    any of them
}