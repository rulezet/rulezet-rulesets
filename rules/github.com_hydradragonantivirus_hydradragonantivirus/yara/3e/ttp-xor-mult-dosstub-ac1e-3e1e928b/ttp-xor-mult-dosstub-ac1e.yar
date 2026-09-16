rule TTP_XOR_MULT_DOSStub_ac1e {
  strings:
    $key_ac1e = { f8 76 [2] 8c 6e [2] cb 6c [2] 8c 7d [2] c2 71 [2] ce 7b [2] d9 70 [2] c2 3e [2] ff }

  condition:
    any of them
}