rule TTP_XOR_MULT_DOSStub_a912 {
  strings:
    $key_a912 = { fd 7a [2] 89 62 [2] ce 60 [2] 89 71 [2] c7 7d [2] cb 77 [2] dc 7c [2] c7 32 [2] fa }

  condition:
    any of them
}