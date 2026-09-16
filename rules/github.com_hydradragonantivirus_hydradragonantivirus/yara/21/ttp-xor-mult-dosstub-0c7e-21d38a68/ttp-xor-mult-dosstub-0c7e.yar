rule TTP_XOR_MULT_DOSStub_0c7e {
  strings:
    $key_0c7e = { 58 16 [2] 2c 0e [2] 6b 0c [2] 2c 1d [2] 62 11 [2] 6e 1b [2] 79 10 [2] 62 5e [2] 5f }

  condition:
    any of them
}