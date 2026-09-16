rule TTP_XOR_MULT_DOSStub_423d {
  strings:
    $key_423d = { 16 55 [2] 62 4d [2] 25 4f [2] 62 5e [2] 2c 52 [2] 20 58 [2] 37 53 [2] 2c 1d [2] 11 }

  condition:
    any of them
}