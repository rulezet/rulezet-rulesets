rule TTP_XOR_MULT_DOSStub_acf9 {
  strings:
    $key_acf9 = { f8 91 [2] 8c 89 [2] cb 8b [2] 8c 9a [2] c2 96 [2] ce 9c [2] d9 97 [2] c2 d9 [2] ff }

  condition:
    any of them
}