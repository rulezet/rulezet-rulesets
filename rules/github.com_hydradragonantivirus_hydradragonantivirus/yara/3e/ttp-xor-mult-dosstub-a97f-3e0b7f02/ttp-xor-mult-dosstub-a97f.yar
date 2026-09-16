rule TTP_XOR_MULT_DOSStub_a97f {
  strings:
    $key_a97f = { fd 17 [2] 89 0f [2] ce 0d [2] 89 1c [2] c7 10 [2] cb 1a [2] dc 11 [2] c7 5f [2] fa }

  condition:
    any of them
}