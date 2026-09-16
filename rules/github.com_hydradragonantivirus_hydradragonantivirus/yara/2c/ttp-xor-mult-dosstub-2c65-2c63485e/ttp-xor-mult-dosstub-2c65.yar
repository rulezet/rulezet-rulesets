rule TTP_XOR_MULT_DOSStub_2c65 {
  strings:
    $key_2c65 = { 78 0d [2] 0c 15 [2] 4b 17 [2] 0c 06 [2] 42 0a [2] 4e 00 [2] 59 0b [2] 42 45 [2] 7f }

  condition:
    any of them
}