rule TTP_XOR_MULT_DOSStub_a53e {
  strings:
    $key_a53e = { f1 56 [2] 85 4e [2] c2 4c [2] 85 5d [2] cb 51 [2] c7 5b [2] d0 50 [2] cb 1e [2] f6 }

  condition:
    any of them
}