rule TTP_XOR_MULT_DOSStub_a97b {
  strings:
    $key_a97b = { fd 13 [2] 89 0b [2] ce 09 [2] 89 18 [2] c7 14 [2] cb 1e [2] dc 15 [2] c7 5b [2] fa }

  condition:
    any of them
}