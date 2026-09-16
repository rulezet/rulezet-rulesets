rule TTP_XOR_MULT_DOSStub_a936 {
  strings:
    $key_a936 = { fd 5e [2] 89 46 [2] ce 44 [2] 89 55 [2] c7 59 [2] cb 53 [2] dc 58 [2] c7 16 [2] fa }

  condition:
    any of them
}