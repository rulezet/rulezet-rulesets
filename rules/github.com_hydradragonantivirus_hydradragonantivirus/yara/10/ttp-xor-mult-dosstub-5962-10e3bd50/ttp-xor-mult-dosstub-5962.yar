rule TTP_XOR_MULT_DOSStub_5962 {
  strings:
    $key_5962 = { 0d 0a [2] 79 12 [2] 3e 10 [2] 79 01 [2] 37 0d [2] 3b 07 [2] 2c 0c [2] 37 42 [2] 0a }

  condition:
    any of them
}