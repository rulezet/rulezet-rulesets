rule TTP_XOR_MULT_DOSStub_ac4a {
  strings:
    $key_ac4a = { f8 22 [2] 8c 3a [2] cb 38 [2] 8c 29 [2] c2 25 [2] ce 2f [2] d9 24 [2] c2 6a [2] ff }

  condition:
    any of them
}