rule TTP_XOR_MULT_DOSStub_a964 {
  strings:
    $key_a964 = { fd 0c [2] 89 14 [2] ce 16 [2] 89 07 [2] c7 0b [2] cb 01 [2] dc 0a [2] c7 44 [2] fa }

  condition:
    any of them
}