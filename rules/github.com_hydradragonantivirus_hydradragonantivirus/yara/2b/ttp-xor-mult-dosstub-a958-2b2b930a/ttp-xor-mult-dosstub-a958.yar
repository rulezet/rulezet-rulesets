rule TTP_XOR_MULT_DOSStub_a958 {
  strings:
    $key_a958 = { fd 30 [2] 89 28 [2] ce 2a [2] 89 3b [2] c7 37 [2] cb 3d [2] dc 36 [2] c7 78 [2] fa }

  condition:
    any of them
}