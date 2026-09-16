rule TTP_XOR_MULT_DOSStub_4e49 {
  strings:
    $key_4e49 = { 1a 21 [2] 6e 39 [2] 29 3b [2] 6e 2a [2] 20 26 [2] 2c 2c [2] 3b 27 [2] 20 69 [2] 1d }

  condition:
    any of them
}