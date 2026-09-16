rule TTP_XOR_MULT_DOSStub_ac4d {
  strings:
    $key_ac4d = { f8 25 [2] 8c 3d [2] cb 3f [2] 8c 2e [2] c2 22 [2] ce 28 [2] d9 23 [2] c2 6d [2] ff }

  condition:
    any of them
}