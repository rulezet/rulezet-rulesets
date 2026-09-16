rule TTP_XOR_MULT_DOSStub_2c48 {
  strings:
    $key_2c48 = { 78 20 [2] 0c 38 [2] 4b 3a [2] 0c 2b [2] 42 27 [2] 4e 2d [2] 59 26 [2] 42 68 [2] 7f }

  condition:
    any of them
}