rule TTP_XOR_MULT_DOSStub_a914 {
  strings:
    $key_a914 = { fd 7c [2] 89 64 [2] ce 66 [2] 89 77 [2] c7 7b [2] cb 71 [2] dc 7a [2] c7 34 [2] fa }

  condition:
    any of them
}