rule TTP_XOR_MULT_DOSStub_a9fa {
  strings:
    $key_a9fa = { fd 92 [2] 89 8a [2] ce 88 [2] 89 99 [2] c7 95 [2] cb 9f [2] dc 94 [2] c7 da [2] fa }

  condition:
    any of them
}