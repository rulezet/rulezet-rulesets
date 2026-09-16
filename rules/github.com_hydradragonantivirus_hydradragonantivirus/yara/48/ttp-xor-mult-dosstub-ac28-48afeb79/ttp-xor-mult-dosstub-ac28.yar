rule TTP_XOR_MULT_DOSStub_ac28 {
  strings:
    $key_ac28 = { f8 40 [2] 8c 58 [2] cb 5a [2] 8c 4b [2] c2 47 [2] ce 4d [2] d9 46 [2] c2 08 [2] ff }

  condition:
    any of them
}