rule TTP_XOR_MULT_DOSStub_0c29 {
  strings:
    $key_0c29 = { 58 41 [2] 2c 59 [2] 6b 5b [2] 2c 4a [2] 62 46 [2] 6e 4c [2] 79 47 [2] 62 09 [2] 5f }

  condition:
    any of them
}