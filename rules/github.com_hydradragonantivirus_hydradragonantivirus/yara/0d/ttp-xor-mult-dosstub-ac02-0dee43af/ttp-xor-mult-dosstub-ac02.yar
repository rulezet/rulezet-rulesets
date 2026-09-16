rule TTP_XOR_MULT_DOSStub_ac02 {
  strings:
    $key_ac02 = { f8 6a [2] 8c 72 [2] cb 70 [2] 8c 61 [2] c2 6d [2] ce 67 [2] d9 6c [2] c2 22 [2] ff }

  condition:
    any of them
}