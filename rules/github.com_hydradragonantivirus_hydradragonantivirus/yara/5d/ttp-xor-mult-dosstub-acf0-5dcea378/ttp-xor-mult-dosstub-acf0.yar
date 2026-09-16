rule TTP_XOR_MULT_DOSStub_acf0 {
  strings:
    $key_acf0 = { f8 98 [2] 8c 80 [2] cb 82 [2] 8c 93 [2] c2 9f [2] ce 95 [2] d9 9e [2] c2 d0 [2] ff }

  condition:
    any of them
}