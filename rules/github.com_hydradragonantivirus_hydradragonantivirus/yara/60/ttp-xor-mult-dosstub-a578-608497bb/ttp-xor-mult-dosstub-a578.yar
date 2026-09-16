rule TTP_XOR_MULT_DOSStub_a578 {
  strings:
    $key_a578 = { f1 10 [2] 85 08 [2] c2 0a [2] 85 1b [2] cb 17 [2] c7 1d [2] d0 16 [2] cb 58 [2] f6 }

  condition:
    any of them
}