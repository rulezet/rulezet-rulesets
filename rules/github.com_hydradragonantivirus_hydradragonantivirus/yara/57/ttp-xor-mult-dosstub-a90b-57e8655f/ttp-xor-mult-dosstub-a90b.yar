rule TTP_XOR_MULT_DOSStub_a90b {
  strings:
    $key_a90b = { fd 63 [2] 89 7b [2] ce 79 [2] 89 68 [2] c7 64 [2] cb 6e [2] dc 65 [2] c7 2b [2] fa }

  condition:
    any of them
}