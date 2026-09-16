rule TTP_XOR_MULT_DOSStub_a969 {
  strings:
    $key_a969 = { fd 01 [2] 89 19 [2] ce 1b [2] 89 0a [2] c7 06 [2] cb 0c [2] dc 07 [2] c7 49 [2] fa }

  condition:
    any of them
}