rule TTP_XOR_MULT_DOSStub_a9e5 {
  strings:
    $key_a9e5 = { fd 8d [2] 89 95 [2] ce 97 [2] 89 86 [2] c7 8a [2] cb 80 [2] dc 8b [2] c7 c5 [2] fa }

  condition:
    any of them
}