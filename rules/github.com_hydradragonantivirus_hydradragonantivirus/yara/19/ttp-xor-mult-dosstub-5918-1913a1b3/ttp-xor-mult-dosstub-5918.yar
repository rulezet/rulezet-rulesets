rule TTP_XOR_MULT_DOSStub_5918 {
  strings:
    $key_5918 = { 0d 70 [2] 79 68 [2] 3e 6a [2] 79 7b [2] 37 77 [2] 3b 7d [2] 2c 76 [2] 37 38 [2] 0a }

  condition:
    any of them
}