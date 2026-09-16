rule TTP_XOR_MULT_DOSStub_a978 {
  strings:
    $key_a978 = { fd 10 [2] 89 08 [2] ce 0a [2] 89 1b [2] c7 17 [2] cb 1d [2] dc 16 [2] c7 58 [2] fa }

  condition:
    any of them
}