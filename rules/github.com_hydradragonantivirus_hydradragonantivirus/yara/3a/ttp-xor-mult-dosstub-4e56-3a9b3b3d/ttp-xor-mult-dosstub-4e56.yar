rule TTP_XOR_MULT_DOSStub_4e56 {
  strings:
    $key_4e56 = { 1a 3e [2] 6e 26 [2] 29 24 [2] 6e 35 [2] 20 39 [2] 2c 33 [2] 3b 38 [2] 20 76 [2] 1d }

  condition:
    any of them
}