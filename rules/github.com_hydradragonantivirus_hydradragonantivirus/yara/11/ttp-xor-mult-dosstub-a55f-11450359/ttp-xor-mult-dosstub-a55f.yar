rule TTP_XOR_MULT_DOSStub_a55f {
  strings:
    $key_a55f = { f1 37 [2] 85 2f [2] c2 2d [2] 85 3c [2] cb 30 [2] c7 3a [2] d0 31 [2] cb 7f [2] f6 }

  condition:
    any of them
}