rule TTP_XOR_MULT_DOSStub_a941 {
  strings:
    $key_a941 = { fd 29 [2] 89 31 [2] ce 33 [2] 89 22 [2] c7 2e [2] cb 24 [2] dc 2f [2] c7 61 [2] fa }

  condition:
    any of them
}