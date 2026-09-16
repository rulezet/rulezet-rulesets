rule TTP_XOR_MULT_DOSStub_ac5d {
  strings:
    $key_ac5d = { f8 35 [2] 8c 2d [2] cb 2f [2] 8c 3e [2] c2 32 [2] ce 38 [2] d9 33 [2] c2 7d [2] ff }

  condition:
    any of them
}