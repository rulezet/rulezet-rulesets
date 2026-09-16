rule TTP_XOR_MULT_DOSStub_a579 {
  strings:
    $key_a579 = { f1 11 [2] 85 09 [2] c2 0b [2] 85 1a [2] cb 16 [2] c7 1c [2] d0 17 [2] cb 59 [2] f6 }

  condition:
    any of them
}