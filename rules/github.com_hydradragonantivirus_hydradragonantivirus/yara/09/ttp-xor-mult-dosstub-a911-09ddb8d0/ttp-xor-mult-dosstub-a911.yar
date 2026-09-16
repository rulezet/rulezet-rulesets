rule TTP_XOR_MULT_DOSStub_a911 {
  strings:
    $key_a911 = { fd 79 [2] 89 61 [2] ce 63 [2] 89 72 [2] c7 7e [2] cb 74 [2] dc 7f [2] c7 31 [2] fa }

  condition:
    any of them
}