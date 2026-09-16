rule TTP_XOR_MULT_DOSStub_4e60 {
  strings:
    $key_4e60 = { 1a 08 [2] 6e 10 [2] 29 12 [2] 6e 03 [2] 20 0f [2] 2c 05 [2] 3b 0e [2] 20 40 [2] 1d }

  condition:
    any of them
}