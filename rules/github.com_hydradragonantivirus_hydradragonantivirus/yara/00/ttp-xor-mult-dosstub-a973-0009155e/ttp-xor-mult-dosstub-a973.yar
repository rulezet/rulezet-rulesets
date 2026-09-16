rule TTP_XOR_MULT_DOSStub_a973 {
  strings:
    $key_a973 = { fd 1b [2] 89 03 [2] ce 01 [2] 89 10 [2] c7 1c [2] cb 16 [2] dc 1d [2] c7 53 [2] fa }

  condition:
    any of them
}