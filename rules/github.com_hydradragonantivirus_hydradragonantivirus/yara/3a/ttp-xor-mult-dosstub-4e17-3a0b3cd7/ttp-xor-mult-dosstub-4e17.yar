rule TTP_XOR_MULT_DOSStub_4e17 {
  strings:
    $key_4e17 = { 1a 7f [2] 6e 67 [2] 29 65 [2] 6e 74 [2] 20 78 [2] 2c 72 [2] 3b 79 [2] 20 37 [2] 1d }

  condition:
    any of them
}