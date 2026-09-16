rule TTP_XOR_MULT_DOSStub_ac32 {
  strings:
    $key_ac32 = { f8 5a [2] 8c 42 [2] cb 40 [2] 8c 51 [2] c2 5d [2] ce 57 [2] d9 5c [2] c2 12 [2] ff }

  condition:
    any of them
}