rule TTP_XOR_MULT_DOSStub_4e6e {
  strings:
    $key_4e6e = { 1a 06 [2] 6e 1e [2] 29 1c [2] 6e 0d [2] 20 01 [2] 2c 0b [2] 3b 00 [2] 20 4e [2] 1d }

  condition:
    any of them
}