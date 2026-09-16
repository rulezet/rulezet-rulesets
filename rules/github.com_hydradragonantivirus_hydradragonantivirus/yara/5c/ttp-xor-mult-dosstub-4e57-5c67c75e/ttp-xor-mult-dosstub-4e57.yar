rule TTP_XOR_MULT_DOSStub_4e57 {
  strings:
    $key_4e57 = { 1a 3f [2] 6e 27 [2] 29 25 [2] 6e 34 [2] 20 38 [2] 2c 32 [2] 3b 39 [2] 20 77 [2] 1d }

  condition:
    any of them
}