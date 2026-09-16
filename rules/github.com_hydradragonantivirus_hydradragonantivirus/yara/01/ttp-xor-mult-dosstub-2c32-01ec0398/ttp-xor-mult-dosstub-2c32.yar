rule TTP_XOR_MULT_DOSStub_2c32 {
  strings:
    $key_2c32 = { 78 5a [2] 0c 42 [2] 4b 40 [2] 0c 51 [2] 42 5d [2] 4e 57 [2] 59 5c [2] 42 12 [2] 7f }

  condition:
    any of them
}