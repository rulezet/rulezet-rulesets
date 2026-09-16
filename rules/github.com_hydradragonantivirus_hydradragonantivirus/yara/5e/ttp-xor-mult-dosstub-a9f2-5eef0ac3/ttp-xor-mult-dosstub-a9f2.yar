rule TTP_XOR_MULT_DOSStub_a9f2 {
  strings:
    $key_a9f2 = { fd 9a [2] 89 82 [2] ce 80 [2] 89 91 [2] c7 9d [2] cb 97 [2] dc 9c [2] c7 d2 [2] fa }

  condition:
    any of them
}