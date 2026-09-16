rule TTP_XOR_MULT_DOSStub_a972 {
  strings:
    $key_a972 = { fd 1a [2] 89 02 [2] ce 00 [2] 89 11 [2] c7 1d [2] cb 17 [2] dc 1c [2] c7 52 [2] fa }

  condition:
    any of them
}