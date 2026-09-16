rule TTP_XOR_MULT_DOSStub_a52a {
  strings:
    $key_a52a = { f1 42 [2] 85 5a [2] c2 58 [2] 85 49 [2] cb 45 [2] c7 4f [2] d0 44 [2] cb 0a [2] f6 }

  condition:
    any of them
}