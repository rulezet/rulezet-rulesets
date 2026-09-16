rule TTP_XOR_MULT_DOSStub_4e07 {
  strings:
    $key_4e07 = { 1a 6f [2] 6e 77 [2] 29 75 [2] 6e 64 [2] 20 68 [2] 2c 62 [2] 3b 69 [2] 20 27 [2] 1d }

  condition:
    any of them
}