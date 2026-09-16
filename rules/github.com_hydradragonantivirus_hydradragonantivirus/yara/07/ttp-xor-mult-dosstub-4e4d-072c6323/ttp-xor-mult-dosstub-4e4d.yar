rule TTP_XOR_MULT_DOSStub_4e4d {
  strings:
    $key_4e4d = { 1a 25 [2] 6e 3d [2] 29 3f [2] 6e 2e [2] 20 22 [2] 2c 28 [2] 3b 23 [2] 20 6d [2] 1d }

  condition:
    any of them
}