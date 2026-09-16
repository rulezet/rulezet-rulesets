rule TTP_XOR_MULT_DOSStub_ac5f {
  strings:
    $key_ac5f = { f8 37 [2] 8c 2f [2] cb 2d [2] 8c 3c [2] c2 30 [2] ce 3a [2] d9 31 [2] c2 7f [2] ff }

  condition:
    any of them
}