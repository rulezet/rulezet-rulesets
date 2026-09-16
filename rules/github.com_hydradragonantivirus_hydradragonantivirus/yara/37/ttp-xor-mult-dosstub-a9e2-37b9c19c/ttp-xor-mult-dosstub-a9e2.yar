rule TTP_XOR_MULT_DOSStub_a9e2 {
  strings:
    $key_a9e2 = { fd 8a [2] 89 92 [2] ce 90 [2] 89 81 [2] c7 8d [2] cb 87 [2] dc 8c [2] c7 c2 [2] fa }

  condition:
    any of them
}