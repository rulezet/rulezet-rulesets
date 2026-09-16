rule TTP_XOR_MULT_DOSStub_5963 {
  strings:
    $key_5963 = { 0d 0b [2] 79 13 [2] 3e 11 [2] 79 00 [2] 37 0c [2] 3b 06 [2] 2c 0d [2] 37 43 [2] 0a }

  condition:
    any of them
}