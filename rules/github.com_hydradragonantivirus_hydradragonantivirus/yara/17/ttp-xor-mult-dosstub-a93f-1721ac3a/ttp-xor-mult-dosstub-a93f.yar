rule TTP_XOR_MULT_DOSStub_a93f {
  strings:
    $key_a93f = { fd 57 [2] 89 4f [2] ce 4d [2] 89 5c [2] c7 50 [2] cb 5a [2] dc 51 [2] c7 1f [2] fa }

  condition:
    any of them
}