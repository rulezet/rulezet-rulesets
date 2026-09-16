rule TTP_XOR_MULT_DOSStub_2c45 {
  strings:
    $key_2c45 = { 78 2d [2] 0c 35 [2] 4b 37 [2] 0c 26 [2] 42 2a [2] 4e 20 [2] 59 2b [2] 42 65 [2] 7f }

  condition:
    any of them
}