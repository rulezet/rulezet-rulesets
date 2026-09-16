rule TTP_XOR_MULT_DOSStub_a94a {
  strings:
    $key_a94a = { fd 22 [2] 89 3a [2] ce 38 [2] 89 29 [2] c7 25 [2] cb 2f [2] dc 24 [2] c7 6a [2] fa }

  condition:
    any of them
}