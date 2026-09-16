rule TTP_XOR_MULT_DOSStub_a913 {
  strings:
    $key_a913 = { fd 7b [2] 89 63 [2] ce 61 [2] 89 70 [2] c7 7c [2] cb 76 [2] dc 7d [2] c7 33 [2] fa }

  condition:
    any of them
}