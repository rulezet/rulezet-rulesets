rule TTP_XOR_MULT_DOSStub_a53a {
  strings:
    $key_a53a = { f1 52 [2] 85 4a [2] c2 48 [2] 85 59 [2] cb 55 [2] c7 5f [2] d0 54 [2] cb 1a [2] f6 }

  condition:
    any of them
}