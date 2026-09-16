rule TTP_XOR_MULT_DOSStub_420d {
  strings:
    $key_420d = { 16 65 [2] 62 7d [2] 25 7f [2] 62 6e [2] 2c 62 [2] 20 68 [2] 37 63 [2] 2c 2d [2] 11 }

  condition:
    any of them
}