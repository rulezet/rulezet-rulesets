rule TTP_XOR_MULT_DOSStub_2c05 {
  strings:
    $key_2c05 = { 78 6d [2] 0c 75 [2] 4b 77 [2] 0c 66 [2] 42 6a [2] 4e 60 [2] 59 6b [2] 42 25 [2] 7f }

  condition:
    any of them
}