rule TTP_XOR_MULT_DOSStub_ac54 {
  strings:
    $key_ac54 = { f8 3c [2] 8c 24 [2] cb 26 [2] 8c 37 [2] c2 3b [2] ce 31 [2] d9 3a [2] c2 74 [2] ff }

  condition:
    any of them
}