rule TTP_XOR_MULT_DOSStub_2c68 {
  strings:
    $key_2c68 = { 78 00 [2] 0c 18 [2] 4b 1a [2] 0c 0b [2] 42 07 [2] 4e 0d [2] 59 06 [2] 42 48 [2] 7f }

  condition:
    any of them
}