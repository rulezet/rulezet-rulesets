rule TTP_XOR_MULT_DOSStub_a952 {
  strings:
    $key_a952 = { fd 3a [2] 89 22 [2] ce 20 [2] 89 31 [2] c7 3d [2] cb 37 [2] dc 3c [2] c7 72 [2] fa }

  condition:
    any of them
}