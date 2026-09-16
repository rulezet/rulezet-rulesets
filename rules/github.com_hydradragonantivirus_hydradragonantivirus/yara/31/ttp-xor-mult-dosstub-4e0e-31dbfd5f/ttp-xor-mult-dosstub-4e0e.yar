rule TTP_XOR_MULT_DOSStub_4e0e {
  strings:
    $key_4e0e = { 1a 66 [2] 6e 7e [2] 29 7c [2] 6e 6d [2] 20 61 [2] 2c 6b [2] 3b 60 [2] 20 2e [2] 1d }

  condition:
    any of them
}