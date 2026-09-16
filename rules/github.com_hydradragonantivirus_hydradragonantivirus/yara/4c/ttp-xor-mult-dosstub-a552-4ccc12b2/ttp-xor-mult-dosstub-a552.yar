rule TTP_XOR_MULT_DOSStub_a552 {
  strings:
    $key_a552 = { f1 3a [2] 85 22 [2] c2 20 [2] 85 31 [2] cb 3d [2] c7 37 [2] d0 3c [2] cb 72 [2] f6 }

  condition:
    any of them
}