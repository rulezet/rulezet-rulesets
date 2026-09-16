rule TTP_XOR_MULT_DOSStub_a904 {
  strings:
    $key_a904 = { fd 6c [2] 89 74 [2] ce 76 [2] 89 67 [2] c7 6b [2] cb 61 [2] dc 6a [2] c7 24 [2] fa }

  condition:
    any of them
}