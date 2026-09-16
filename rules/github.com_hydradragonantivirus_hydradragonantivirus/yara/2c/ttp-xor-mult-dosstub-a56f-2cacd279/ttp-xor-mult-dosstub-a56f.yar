rule TTP_XOR_MULT_DOSStub_a56f {
  strings:
    $key_a56f = { f1 07 [2] 85 1f [2] c2 1d [2] 85 0c [2] cb 00 [2] c7 0a [2] d0 01 [2] cb 4f [2] f6 }

  condition:
    any of them
}