rule TTP_XOR_MULT_DOSStub_4e62 {
  strings:
    $key_4e62 = { 1a 0a [2] 6e 12 [2] 29 10 [2] 6e 01 [2] 20 0d [2] 2c 07 [2] 3b 0c [2] 20 42 [2] 1d }

  condition:
    any of them
}