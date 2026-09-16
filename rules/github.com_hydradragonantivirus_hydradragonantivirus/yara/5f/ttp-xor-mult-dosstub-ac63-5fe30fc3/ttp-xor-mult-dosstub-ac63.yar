rule TTP_XOR_MULT_DOSStub_ac63 {
  strings:
    $key_ac63 = { f8 0b [2] 8c 13 [2] cb 11 [2] 8c 00 [2] c2 0c [2] ce 06 [2] d9 0d [2] c2 43 [2] ff }

  condition:
    any of them
}