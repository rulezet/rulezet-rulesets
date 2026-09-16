rule TTP_XOR_MULT_DOSStub_a949 {
  strings:
    $key_a949 = { fd 21 [2] 89 39 [2] ce 3b [2] 89 2a [2] c7 26 [2] cb 2c [2] dc 27 [2] c7 69 [2] fa }

  condition:
    any of them
}