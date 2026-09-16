rule TTP_XOR_MULT_DOSStub_4e36 {
  strings:
    $key_4e36 = { 1a 5e [2] 6e 46 [2] 29 44 [2] 6e 55 [2] 20 59 [2] 2c 53 [2] 3b 58 [2] 20 16 [2] 1d }

  condition:
    any of them
}