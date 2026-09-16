rule TTP_XOR_MULT_DOSStub_0c25 {
  strings:
    $key_0c25 = { 58 4d [2] 2c 55 [2] 6b 57 [2] 2c 46 [2] 62 4a [2] 6e 40 [2] 79 4b [2] 62 05 [2] 5f }

  condition:
    any of them
}