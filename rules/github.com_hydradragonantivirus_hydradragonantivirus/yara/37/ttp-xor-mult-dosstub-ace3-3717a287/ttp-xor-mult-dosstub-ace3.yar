rule TTP_XOR_MULT_DOSStub_ace3 {
  strings:
    $key_ace3 = { f8 8b [2] 8c 93 [2] cb 91 [2] 8c 80 [2] c2 8c [2] ce 86 [2] d9 8d [2] c2 c3 [2] ff }

  condition:
    any of them
}