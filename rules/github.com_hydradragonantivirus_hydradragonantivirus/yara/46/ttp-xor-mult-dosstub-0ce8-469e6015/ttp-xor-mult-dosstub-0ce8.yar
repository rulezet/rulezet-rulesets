rule TTP_XOR_MULT_DOSStub_0ce8 {
  strings:
    $key_0ce8 = { 58 80 [2] 2c 98 [2] 6b 9a [2] 2c 8b [2] 62 87 [2] 6e 8d [2] 79 86 [2] 62 c8 [2] 5f }

  condition:
    any of them
}