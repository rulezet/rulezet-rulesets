rule TTP_XOR_MULT_DOSStub_a50e {
  strings:
    $key_a50e = { f1 66 [2] 85 7e [2] c2 7c [2] 85 6d [2] cb 61 [2] c7 6b [2] d0 60 [2] cb 2e [2] f6 }

  condition:
    any of them
}