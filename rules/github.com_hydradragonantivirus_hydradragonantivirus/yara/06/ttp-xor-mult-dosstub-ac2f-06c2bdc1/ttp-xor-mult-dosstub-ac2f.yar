rule TTP_XOR_MULT_DOSStub_ac2f {
  strings:
    $key_ac2f = { f8 47 [2] 8c 5f [2] cb 5d [2] 8c 4c [2] c2 40 [2] ce 4a [2] d9 41 [2] c2 0f [2] ff }

  condition:
    any of them
}