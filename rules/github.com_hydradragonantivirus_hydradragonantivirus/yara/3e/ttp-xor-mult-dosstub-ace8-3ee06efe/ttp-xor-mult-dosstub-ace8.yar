rule TTP_XOR_MULT_DOSStub_ace8 {
  strings:
    $key_ace8 = { f8 80 [2] 8c 98 [2] cb 9a [2] 8c 8b [2] c2 87 [2] ce 8d [2] d9 86 [2] c2 c8 [2] ff }

  condition:
    any of them
}