rule TTP_XOR_MULT_DOSStub_4e30 {
  strings:
    $key_4e30 = { 1a 58 [2] 6e 40 [2] 29 42 [2] 6e 53 [2] 20 5f [2] 2c 55 [2] 3b 5e [2] 20 10 [2] 1d }

  condition:
    any of them
}