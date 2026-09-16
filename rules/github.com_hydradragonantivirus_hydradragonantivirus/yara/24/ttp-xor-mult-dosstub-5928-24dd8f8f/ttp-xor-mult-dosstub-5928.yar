rule TTP_XOR_MULT_DOSStub_5928 {
  strings:
    $key_5928 = { 0d 40 [2] 79 58 [2] 3e 5a [2] 79 4b [2] 37 47 [2] 3b 4d [2] 2c 46 [2] 37 08 [2] 0a }

  condition:
    any of them
}