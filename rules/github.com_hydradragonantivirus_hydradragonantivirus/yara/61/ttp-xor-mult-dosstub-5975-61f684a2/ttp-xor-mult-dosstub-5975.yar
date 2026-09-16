rule TTP_XOR_MULT_DOSStub_5975 {
  strings:
    $key_5975 = { 0d 1d [2] 79 05 [2] 3e 07 [2] 79 16 [2] 37 1a [2] 3b 10 [2] 2c 1b [2] 37 55 [2] 0a }

  condition:
    any of them
}