rule TTP_XOR_MULT_DOSStub_5907 {
  strings:
    $key_5907 = { 0d 6f [2] 79 77 [2] 3e 75 [2] 79 64 [2] 37 68 [2] 3b 62 [2] 2c 69 [2] 37 27 [2] 0a }

  condition:
    any of them
}