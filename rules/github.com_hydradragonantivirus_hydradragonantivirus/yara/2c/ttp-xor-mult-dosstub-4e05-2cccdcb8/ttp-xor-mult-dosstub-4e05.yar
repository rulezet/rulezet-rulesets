rule TTP_XOR_MULT_DOSStub_4e05 {
  strings:
    $key_4e05 = { 1a 6d [2] 6e 75 [2] 29 77 [2] 6e 66 [2] 20 6a [2] 2c 60 [2] 3b 6b [2] 20 25 [2] 1d }

  condition:
    any of them
}