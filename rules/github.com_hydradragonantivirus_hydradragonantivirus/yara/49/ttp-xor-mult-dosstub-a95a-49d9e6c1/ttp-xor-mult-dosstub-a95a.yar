rule TTP_XOR_MULT_DOSStub_a95a {
  strings:
    $key_a95a = { fd 32 [2] 89 2a [2] ce 28 [2] 89 39 [2] c7 35 [2] cb 3f [2] dc 34 [2] c7 7a [2] fa }

  condition:
    any of them
}