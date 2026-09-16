rule TTP_XOR_MULT_DOSStub_4e70 {
  strings:
    $key_4e70 = { 1a 18 [2] 6e 00 [2] 29 02 [2] 6e 13 [2] 20 1f [2] 2c 15 [2] 3b 1e [2] 20 50 [2] 1d }

  condition:
    any of them
}