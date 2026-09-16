rule TTP_XOR_MULT_DOSStub_a572 {
  strings:
    $key_a572 = { f1 1a [2] 85 02 [2] c2 00 [2] 85 11 [2] cb 1d [2] c7 17 [2] d0 1c [2] cb 52 [2] f6 }

  condition:
    any of them
}