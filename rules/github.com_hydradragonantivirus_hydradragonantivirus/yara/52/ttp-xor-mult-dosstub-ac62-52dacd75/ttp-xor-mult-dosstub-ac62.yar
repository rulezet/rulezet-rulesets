rule TTP_XOR_MULT_DOSStub_ac62 {
  strings:
    $key_ac62 = { f8 0a [2] 8c 12 [2] cb 10 [2] 8c 01 [2] c2 0d [2] ce 07 [2] d9 0c [2] c2 42 [2] ff }

  condition:
    any of them
}