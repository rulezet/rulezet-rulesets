rule TTP_XOR_MULT_DOSStub_2c72 {
  strings:
    $key_2c72 = { 78 1a [2] 0c 02 [2] 4b 00 [2] 0c 11 [2] 42 1d [2] 4e 17 [2] 59 1c [2] 42 52 [2] 7f }

  condition:
    any of them
}