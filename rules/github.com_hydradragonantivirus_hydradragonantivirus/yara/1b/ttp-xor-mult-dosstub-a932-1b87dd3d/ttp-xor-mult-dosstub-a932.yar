rule TTP_XOR_MULT_DOSStub_a932 {
  strings:
    $key_a932 = { fd 5a [2] 89 42 [2] ce 40 [2] 89 51 [2] c7 5d [2] cb 57 [2] dc 5c [2] c7 12 [2] fa }

  condition:
    any of them
}