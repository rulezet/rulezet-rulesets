rule TTP_XOR_MULT_DOSStub_a90c {
  strings:
    $key_a90c = { fd 64 [2] 89 7c [2] ce 7e [2] 89 6f [2] c7 63 [2] cb 69 [2] dc 62 [2] c7 2c [2] fa }

  condition:
    any of them
}