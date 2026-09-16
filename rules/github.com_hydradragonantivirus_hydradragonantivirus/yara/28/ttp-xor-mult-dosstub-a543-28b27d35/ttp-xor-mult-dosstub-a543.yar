rule TTP_XOR_MULT_DOSStub_a543 {
  strings:
    $key_a543 = { f1 2b [2] 85 33 [2] c2 31 [2] 85 20 [2] cb 2c [2] c7 26 [2] d0 2d [2] cb 63 [2] f6 }

  condition:
    any of them
}