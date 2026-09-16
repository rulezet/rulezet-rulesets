rule TTP_XOR_MULT_DOSStub_a50a {
  strings:
    $key_a50a = { f1 62 [2] 85 7a [2] c2 78 [2] 85 69 [2] cb 65 [2] c7 6f [2] d0 64 [2] cb 2a [2] f6 }

  condition:
    any of them
}