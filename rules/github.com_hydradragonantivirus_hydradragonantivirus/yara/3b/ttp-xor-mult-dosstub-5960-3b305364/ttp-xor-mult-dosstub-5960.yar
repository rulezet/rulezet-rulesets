rule TTP_XOR_MULT_DOSStub_5960 {
  strings:
    $key_5960 = { 0d 08 [2] 79 10 [2] 3e 12 [2] 79 03 [2] 37 0f [2] 3b 05 [2] 2c 0e [2] 37 40 [2] 0a }

  condition:
    any of them
}