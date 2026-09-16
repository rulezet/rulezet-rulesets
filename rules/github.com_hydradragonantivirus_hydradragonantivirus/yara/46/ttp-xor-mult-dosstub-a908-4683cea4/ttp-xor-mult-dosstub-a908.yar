rule TTP_XOR_MULT_DOSStub_a908 {
  strings:
    $key_a908 = { fd 60 [2] 89 78 [2] ce 7a [2] 89 6b [2] c7 67 [2] cb 6d [2] dc 66 [2] c7 28 [2] fa }

  condition:
    any of them
}