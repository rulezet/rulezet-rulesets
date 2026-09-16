rule TTP_XOR_MULT_DOSStub_4e31 {
  strings:
    $key_4e31 = { 1a 59 [2] 6e 41 [2] 29 43 [2] 6e 52 [2] 20 5e [2] 2c 54 [2] 3b 5f [2] 20 11 [2] 1d }

  condition:
    any of them
}