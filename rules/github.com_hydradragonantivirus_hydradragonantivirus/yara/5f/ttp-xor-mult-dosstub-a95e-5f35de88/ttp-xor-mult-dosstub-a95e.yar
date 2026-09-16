rule TTP_XOR_MULT_DOSStub_a95e {
  strings:
    $key_a95e = { fd 36 [2] 89 2e [2] ce 2c [2] 89 3d [2] c7 31 [2] cb 3b [2] dc 30 [2] c7 7e [2] fa }

  condition:
    any of them
}