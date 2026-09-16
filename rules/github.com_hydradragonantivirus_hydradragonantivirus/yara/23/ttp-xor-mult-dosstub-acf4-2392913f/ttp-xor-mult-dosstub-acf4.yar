rule TTP_XOR_MULT_DOSStub_acf4 {
  strings:
    $key_acf4 = { f8 9c [2] 8c 84 [2] cb 86 [2] 8c 97 [2] c2 9b [2] ce 91 [2] d9 9a [2] c2 d4 [2] ff }

  condition:
    any of them
}