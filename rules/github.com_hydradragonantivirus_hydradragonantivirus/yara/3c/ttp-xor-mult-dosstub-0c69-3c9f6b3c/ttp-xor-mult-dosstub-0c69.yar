rule TTP_XOR_MULT_DOSStub_0c69 {
  strings:
    $key_0c69 = { 58 01 [2] 2c 19 [2] 6b 1b [2] 2c 0a [2] 62 06 [2] 6e 0c [2] 79 07 [2] 62 49 [2] 5f }

  condition:
    any of them
}