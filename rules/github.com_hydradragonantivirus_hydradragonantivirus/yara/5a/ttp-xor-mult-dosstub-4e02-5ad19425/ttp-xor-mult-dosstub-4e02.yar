rule TTP_XOR_MULT_DOSStub_4e02 {
  strings:
    $key_4e02 = { 1a 6a [2] 6e 72 [2] 29 70 [2] 6e 61 [2] 20 6d [2] 2c 67 [2] 3b 6c [2] 20 22 [2] 1d }

  condition:
    any of them
}