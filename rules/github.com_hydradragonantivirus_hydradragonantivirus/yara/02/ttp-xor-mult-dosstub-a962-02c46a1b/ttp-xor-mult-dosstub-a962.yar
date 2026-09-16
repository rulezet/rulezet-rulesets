rule TTP_XOR_MULT_DOSStub_a962 {
  strings:
    $key_a962 = { fd 0a [2] 89 12 [2] ce 10 [2] 89 01 [2] c7 0d [2] cb 07 [2] dc 0c [2] c7 42 [2] fa }

  condition:
    any of them
}