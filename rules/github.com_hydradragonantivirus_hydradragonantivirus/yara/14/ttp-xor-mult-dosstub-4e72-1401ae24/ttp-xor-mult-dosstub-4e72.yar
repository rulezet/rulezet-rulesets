rule TTP_XOR_MULT_DOSStub_4e72 {
  strings:
    $key_4e72 = { 1a 1a [2] 6e 02 [2] 29 00 [2] 6e 11 [2] 20 1d [2] 2c 17 [2] 3b 1c [2] 20 52 [2] 1d }

  condition:
    any of them
}