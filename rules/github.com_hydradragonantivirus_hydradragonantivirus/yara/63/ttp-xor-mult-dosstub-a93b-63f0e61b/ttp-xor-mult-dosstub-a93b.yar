rule TTP_XOR_MULT_DOSStub_a93b {
  strings:
    $key_a93b = { fd 53 [2] 89 4b [2] ce 49 [2] 89 58 [2] c7 54 [2] cb 5e [2] dc 55 [2] c7 1b [2] fa }

  condition:
    any of them
}