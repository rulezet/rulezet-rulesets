rule TTP_XOR_MULT_DOSStub_a52e {
  strings:
    $key_a52e = { f1 46 [2] 85 5e [2] c2 5c [2] 85 4d [2] cb 41 [2] c7 4b [2] d0 40 [2] cb 0e [2] f6 }

  condition:
    any of them
}