rule TTP_XOR_MULT_DOSStub_5973 {
  strings:
    $key_5973 = { 0d 1b [2] 79 03 [2] 3e 01 [2] 79 10 [2] 37 1c [2] 3b 16 [2] 2c 1d [2] 37 53 [2] 0a }

  condition:
    any of them
}