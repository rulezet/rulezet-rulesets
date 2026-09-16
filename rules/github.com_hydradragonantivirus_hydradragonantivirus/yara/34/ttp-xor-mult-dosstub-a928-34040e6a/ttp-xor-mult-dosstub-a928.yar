rule TTP_XOR_MULT_DOSStub_a928 {
  strings:
    $key_a928 = { fd 40 [2] 89 58 [2] ce 5a [2] 89 4b [2] c7 47 [2] cb 4d [2] dc 46 [2] c7 08 [2] fa }

  condition:
    any of them
}