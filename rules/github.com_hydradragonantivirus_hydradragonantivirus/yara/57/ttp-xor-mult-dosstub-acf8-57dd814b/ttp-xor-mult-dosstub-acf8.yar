rule TTP_XOR_MULT_DOSStub_acf8 {
  strings:
    $key_acf8 = { f8 90 [2] 8c 88 [2] cb 8a [2] 8c 9b [2] c2 97 [2] ce 9d [2] d9 96 [2] c2 d8 [2] ff }

  condition:
    any of them
}