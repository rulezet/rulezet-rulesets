rule TTP_XOR_MULT_DOSStub_ac7e {
  strings:
    $key_ac7e = { f8 16 [2] 8c 0e [2] cb 0c [2] 8c 1d [2] c2 11 [2] ce 1b [2] d9 10 [2] c2 5e [2] ff }

  condition:
    any of them
}