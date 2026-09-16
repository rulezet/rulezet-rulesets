rule TTP_XOR_MULT_DOSStub_4e5e {
  strings:
    $key_4e5e = { 1a 36 [2] 6e 2e [2] 29 2c [2] 6e 3d [2] 20 31 [2] 2c 3b [2] 3b 30 [2] 20 7e [2] 1d }

  condition:
    any of them
}