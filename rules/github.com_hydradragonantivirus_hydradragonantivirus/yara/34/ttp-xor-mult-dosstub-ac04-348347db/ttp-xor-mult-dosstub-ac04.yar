rule TTP_XOR_MULT_DOSStub_ac04 {
  strings:
    $key_ac04 = { f8 6c [2] 8c 74 [2] cb 76 [2] 8c 67 [2] c2 6b [2] ce 61 [2] d9 6a [2] c2 24 [2] ff }

  condition:
    any of them
}