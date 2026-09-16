rule TTP_XOR_MULT_DOSStub_a926 {
  strings:
    $key_a926 = { fd 4e [2] 89 56 [2] ce 54 [2] 89 45 [2] c7 49 [2] cb 43 [2] dc 48 [2] c7 06 [2] fa }

  condition:
    any of them
}