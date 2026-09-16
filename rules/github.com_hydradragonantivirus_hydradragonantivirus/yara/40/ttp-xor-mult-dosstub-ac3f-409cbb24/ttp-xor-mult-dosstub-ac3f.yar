rule TTP_XOR_MULT_DOSStub_ac3f {
  strings:
    $key_ac3f = { f8 57 [2] 8c 4f [2] cb 4d [2] 8c 5c [2] c2 50 [2] ce 5a [2] d9 51 [2] c2 1f [2] ff }

  condition:
    any of them
}