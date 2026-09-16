rule TTP_XOR_MULT_DOSStub_4279 {
  strings:
    $key_4279 = { 16 11 [2] 62 09 [2] 25 0b [2] 62 1a [2] 2c 16 [2] 20 1c [2] 37 17 [2] 2c 59 [2] 11 }

  condition:
    any of them
}