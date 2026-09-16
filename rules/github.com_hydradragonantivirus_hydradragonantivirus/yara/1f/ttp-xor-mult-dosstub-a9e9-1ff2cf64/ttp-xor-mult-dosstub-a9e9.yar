rule TTP_XOR_MULT_DOSStub_a9e9 {
  strings:
    $key_a9e9 = { fd 81 [2] 89 99 [2] ce 9b [2] 89 8a [2] c7 86 [2] cb 8c [2] dc 87 [2] c7 c9 [2] fa }

  condition:
    any of them
}