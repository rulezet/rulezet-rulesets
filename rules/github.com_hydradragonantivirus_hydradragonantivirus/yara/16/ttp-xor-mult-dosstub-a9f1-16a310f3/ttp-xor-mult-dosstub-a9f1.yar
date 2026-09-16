rule TTP_XOR_MULT_DOSStub_a9f1 {
  strings:
    $key_a9f1 = { fd 99 [2] 89 81 [2] ce 83 [2] 89 92 [2] c7 9e [2] cb 94 [2] dc 9f [2] c7 d1 [2] fa }

  condition:
    any of them
}