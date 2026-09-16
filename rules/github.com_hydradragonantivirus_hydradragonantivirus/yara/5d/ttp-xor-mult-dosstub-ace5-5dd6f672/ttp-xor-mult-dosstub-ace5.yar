rule TTP_XOR_MULT_DOSStub_ace5 {
  strings:
    $key_ace5 = { f8 8d [2] 8c 95 [2] cb 97 [2] 8c 86 [2] c2 8a [2] ce 80 [2] d9 8b [2] c2 c5 [2] ff }

  condition:
    any of them
}