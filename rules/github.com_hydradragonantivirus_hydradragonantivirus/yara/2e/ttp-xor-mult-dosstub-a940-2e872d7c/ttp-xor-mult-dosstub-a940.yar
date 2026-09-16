rule TTP_XOR_MULT_DOSStub_a940 {
  strings:
    $key_a940 = { fd 28 [2] 89 30 [2] ce 32 [2] 89 23 [2] c7 2f [2] cb 25 [2] dc 2e [2] c7 60 [2] fa }

  condition:
    any of them
}