rule TTP_XOR_MULT_DOSStub_4205 {
  strings:
    $key_4205 = { 16 6d [2] 62 75 [2] 25 77 [2] 62 66 [2] 2c 6a [2] 20 60 [2] 37 6b [2] 2c 25 [2] 11 }

  condition:
    any of them
}