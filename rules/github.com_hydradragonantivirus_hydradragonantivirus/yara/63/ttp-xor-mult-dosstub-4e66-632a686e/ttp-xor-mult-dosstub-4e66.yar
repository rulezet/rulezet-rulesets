rule TTP_XOR_MULT_DOSStub_4e66 {
  strings:
    $key_4e66 = { 1a 0e [2] 6e 16 [2] 29 14 [2] 6e 05 [2] 20 09 [2] 2c 03 [2] 3b 08 [2] 20 46 [2] 1d }

  condition:
    any of them
}