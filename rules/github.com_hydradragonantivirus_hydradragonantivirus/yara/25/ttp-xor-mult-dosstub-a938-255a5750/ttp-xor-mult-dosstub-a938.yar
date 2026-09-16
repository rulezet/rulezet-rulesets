rule TTP_XOR_MULT_DOSStub_a938 {
  strings:
    $key_a938 = { fd 50 [2] 89 48 [2] ce 4a [2] 89 5b [2] c7 57 [2] cb 5d [2] dc 56 [2] c7 18 [2] fa }

  condition:
    any of them
}