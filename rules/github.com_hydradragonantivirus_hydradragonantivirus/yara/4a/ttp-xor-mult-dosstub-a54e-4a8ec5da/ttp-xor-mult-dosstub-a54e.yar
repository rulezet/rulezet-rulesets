rule TTP_XOR_MULT_DOSStub_a54e {
  strings:
    $key_a54e = { f1 26 [2] 85 3e [2] c2 3c [2] 85 2d [2] cb 21 [2] c7 2b [2] d0 20 [2] cb 6e [2] f6 }

  condition:
    any of them
}