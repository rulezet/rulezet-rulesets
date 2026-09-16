rule TTP_XOR_MULT_DOSStub_5954 {
  strings:
    $key_5954 = { 0d 3c [2] 79 24 [2] 3e 26 [2] 79 37 [2] 37 3b [2] 3b 31 [2] 2c 3a [2] 37 74 [2] 0a }

  condition:
    any of them
}