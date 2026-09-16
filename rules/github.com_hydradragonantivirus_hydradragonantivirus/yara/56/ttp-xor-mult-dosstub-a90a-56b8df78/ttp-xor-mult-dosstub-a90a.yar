rule TTP_XOR_MULT_DOSStub_a90a {
  strings:
    $key_a90a = { fd 62 [2] 89 7a [2] ce 78 [2] 89 69 [2] c7 65 [2] cb 6f [2] dc 64 [2] c7 2a [2] fa }

  condition:
    any of them
}