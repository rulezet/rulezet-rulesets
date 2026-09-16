rule TTP_XOR_MULT_DOSStub_0c2e {
  strings:
    $key_0c2e = { 58 46 [2] 2c 5e [2] 6b 5c [2] 2c 4d [2] 62 41 [2] 6e 4b [2] 79 40 [2] 62 0e [2] 5f }

  condition:
    any of them
}