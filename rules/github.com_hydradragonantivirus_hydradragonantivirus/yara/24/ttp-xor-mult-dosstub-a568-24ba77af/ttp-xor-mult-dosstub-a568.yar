rule TTP_XOR_MULT_DOSStub_a568 {
  strings:
    $key_a568 = { f1 00 [2] 85 18 [2] c2 1a [2] 85 0b [2] cb 07 [2] c7 0d [2] d0 06 [2] cb 48 [2] f6 }

  condition:
    any of them
}