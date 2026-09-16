rule TTP_XOR_MULT_DOSStub_a9f0 {
  strings:
    $key_a9f0 = { fd 98 [2] 89 80 [2] ce 82 [2] 89 93 [2] c7 9f [2] cb 95 [2] dc 9e [2] c7 d0 [2] fa }

  condition:
    any of them
}