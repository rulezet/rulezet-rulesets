rule TTP_XOR_MULT_DOSStub_a946 {
  strings:
    $key_a946 = { fd 2e [2] 89 36 [2] ce 34 [2] 89 25 [2] c7 29 [2] cb 23 [2] dc 28 [2] c7 66 [2] fa }

  condition:
    any of them
}