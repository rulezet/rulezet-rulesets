rule TTP_XOR_MULT_DOSStub_5910 {
  strings:
    $key_5910 = { 0d 78 [2] 79 60 [2] 3e 62 [2] 79 73 [2] 37 7f [2] 3b 75 [2] 2c 7e [2] 37 30 [2] 0a }

  condition:
    any of them
}