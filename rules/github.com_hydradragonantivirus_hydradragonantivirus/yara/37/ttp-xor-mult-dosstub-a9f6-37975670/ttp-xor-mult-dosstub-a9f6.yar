rule TTP_XOR_MULT_DOSStub_a9f6 {
  strings:
    $key_a9f6 = { fd 9e [2] 89 86 [2] ce 84 [2] 89 95 [2] c7 99 [2] cb 93 [2] dc 98 [2] c7 d6 [2] fa }

  condition:
    any of them
}