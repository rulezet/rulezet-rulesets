rule TTP_XOR_MULT_DOSStub_a97e {
  strings:
    $key_a97e = { fd 16 [2] 89 0e [2] ce 0c [2] 89 1d [2] c7 11 [2] cb 1b [2] dc 10 [2] c7 5e [2] fa }

  condition:
    any of them
}