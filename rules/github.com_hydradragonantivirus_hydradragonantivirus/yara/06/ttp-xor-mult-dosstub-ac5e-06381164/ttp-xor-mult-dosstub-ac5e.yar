rule TTP_XOR_MULT_DOSStub_ac5e {
  strings:
    $key_ac5e = { f8 36 [2] 8c 2e [2] cb 2c [2] 8c 3d [2] c2 31 [2] ce 3b [2] d9 30 [2] c2 7e [2] ff }

  condition:
    any of them
}