rule TTP_XOR_MULT_DOSStub_acf2 {
  strings:
    $key_acf2 = { f8 9a [2] 8c 82 [2] cb 80 [2] 8c 91 [2] c2 9d [2] ce 97 [2] d9 9c [2] c2 d2 [2] ff }

  condition:
    any of them
}