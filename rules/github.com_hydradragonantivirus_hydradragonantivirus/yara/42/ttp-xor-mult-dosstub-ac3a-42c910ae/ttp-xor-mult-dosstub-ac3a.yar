rule TTP_XOR_MULT_DOSStub_ac3a {
  strings:
    $key_ac3a = { f8 52 [2] 8c 4a [2] cb 48 [2] 8c 59 [2] c2 55 [2] ce 5f [2] d9 54 [2] c2 1a [2] ff }

  condition:
    any of them
}