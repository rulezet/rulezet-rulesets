rule TTP_XOR_MULT_DOSStub_a56a {
  strings:
    $key_a56a = { f1 02 [2] 85 1a [2] c2 18 [2] 85 09 [2] cb 05 [2] c7 0f [2] d0 04 [2] cb 4a [2] f6 }

  condition:
    any of them
}