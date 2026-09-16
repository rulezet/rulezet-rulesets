rule TTP_XOR_MULT_DOSStub_5974 {
  strings:
    $key_5974 = { 0d 1c [2] 79 04 [2] 3e 06 [2] 79 17 [2] 37 1b [2] 3b 11 [2] 2c 1a [2] 37 54 [2] 0a }

  condition:
    any of them
}