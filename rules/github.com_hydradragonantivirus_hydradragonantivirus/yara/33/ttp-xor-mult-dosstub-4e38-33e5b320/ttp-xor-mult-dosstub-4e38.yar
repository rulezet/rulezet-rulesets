rule TTP_XOR_MULT_DOSStub_4e38 {
  strings:
    $key_4e38 = { 1a 50 [2] 6e 48 [2] 29 4a [2] 6e 5b [2] 20 57 [2] 2c 5d [2] 3b 56 [2] 20 18 [2] 1d }

  condition:
    any of them
}