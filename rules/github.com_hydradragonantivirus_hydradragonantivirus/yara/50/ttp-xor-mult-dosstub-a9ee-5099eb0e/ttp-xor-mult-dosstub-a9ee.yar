rule TTP_XOR_MULT_DOSStub_a9ee {
  strings:
    $key_a9ee = { fd 86 [2] 89 9e [2] ce 9c [2] 89 8d [2] c7 81 [2] cb 8b [2] dc 80 [2] c7 ce [2] fa }

  condition:
    any of them
}