rule TTP_XOR_MULT_DOSStub_4e16 {
  strings:
    $key_4e16 = { 1a 7e [2] 6e 66 [2] 29 64 [2] 6e 75 [2] 20 79 [2] 2c 73 [2] 3b 78 [2] 20 36 [2] 1d }

  condition:
    any of them
}