rule TTP_XOR_MULT_DOSStub_2c75 {
  strings:
    $key_2c75 = { 78 1d [2] 0c 05 [2] 4b 07 [2] 0c 16 [2] 42 1a [2] 4e 10 [2] 59 1b [2] 42 55 [2] 7f }

  condition:
    any of them
}