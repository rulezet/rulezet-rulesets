rule TTP_XOR_MULT_DOSStub_ac48 {
  strings:
    $key_ac48 = { f8 20 [2] 8c 38 [2] cb 3a [2] 8c 2b [2] c2 27 [2] ce 2d [2] d9 26 [2] c2 68 [2] ff }

  condition:
    any of them
}