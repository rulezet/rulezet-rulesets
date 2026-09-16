rule TTP_XOR_MULT_DOSStub_a979 {
  strings:
    $key_a979 = { fd 11 [2] 89 09 [2] ce 0b [2] 89 1a [2] c7 16 [2] cb 1c [2] dc 17 [2] c7 59 [2] fa }

  condition:
    any of them
}