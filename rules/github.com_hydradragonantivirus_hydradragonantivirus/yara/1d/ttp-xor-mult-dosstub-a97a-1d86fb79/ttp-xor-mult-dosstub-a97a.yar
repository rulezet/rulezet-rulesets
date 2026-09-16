rule TTP_XOR_MULT_DOSStub_a97a {
  strings:
    $key_a97a = { fd 12 [2] 89 0a [2] ce 08 [2] 89 19 [2] c7 15 [2] cb 1f [2] dc 14 [2] c7 5a [2] fa }

  condition:
    any of them
}