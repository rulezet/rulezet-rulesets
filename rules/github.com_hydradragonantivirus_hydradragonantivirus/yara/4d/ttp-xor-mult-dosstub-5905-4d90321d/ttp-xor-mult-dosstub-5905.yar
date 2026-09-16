rule TTP_XOR_MULT_DOSStub_5905 {
  strings:
    $key_5905 = { 0d 6d [2] 79 75 [2] 3e 77 [2] 79 66 [2] 37 6a [2] 3b 60 [2] 2c 6b [2] 37 25 [2] 0a }

  condition:
    any of them
}