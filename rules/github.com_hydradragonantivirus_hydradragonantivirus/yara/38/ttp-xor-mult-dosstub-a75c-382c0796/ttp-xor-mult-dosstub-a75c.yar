rule TTP_XOR_MULT_DOSStub_a75c {
  strings:
    $key_a75c = { f3 34 [2] 87 2c [2] c0 2e [2] 87 3f [2] c9 33 [2] c5 39 [2] d2 32 [2] c9 7c [2] f4 }

  condition:
    any of them
}