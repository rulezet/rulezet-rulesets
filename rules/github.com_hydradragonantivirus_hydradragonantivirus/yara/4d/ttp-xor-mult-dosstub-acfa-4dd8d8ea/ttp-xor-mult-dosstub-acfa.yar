rule TTP_XOR_MULT_DOSStub_acfa {
  strings:
    $key_acfa = { f8 92 [2] 8c 8a [2] cb 88 [2] 8c 99 [2] c2 95 [2] ce 9f [2] d9 94 [2] c2 da [2] ff }

  condition:
    any of them
}