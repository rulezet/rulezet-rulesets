rule TTP_XOR_MULT_DOSStub_5937 {
  strings:
    $key_5937 = { 0d 5f [2] 79 47 [2] 3e 45 [2] 79 54 [2] 37 58 [2] 3b 52 [2] 2c 59 [2] 37 17 [2] 0a }

  condition:
    any of them
}