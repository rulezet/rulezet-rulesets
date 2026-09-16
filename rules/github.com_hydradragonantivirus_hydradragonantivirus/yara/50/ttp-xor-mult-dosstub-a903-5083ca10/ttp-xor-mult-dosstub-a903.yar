rule TTP_XOR_MULT_DOSStub_a903 {
  strings:
    $key_a903 = { fd 6b [2] 89 73 [2] ce 71 [2] 89 60 [2] c7 6c [2] cb 66 [2] dc 6d [2] c7 23 [2] fa }

  condition:
    any of them
}