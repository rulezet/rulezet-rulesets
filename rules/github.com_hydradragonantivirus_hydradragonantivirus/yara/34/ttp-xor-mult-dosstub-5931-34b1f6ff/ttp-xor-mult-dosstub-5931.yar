rule TTP_XOR_MULT_DOSStub_5931 {
  strings:
    $key_5931 = { 0d 59 [2] 79 41 [2] 3e 43 [2] 79 52 [2] 37 5e [2] 3b 54 [2] 2c 5f [2] 37 11 [2] 0a }

  condition:
    any of them
}