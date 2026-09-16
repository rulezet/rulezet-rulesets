rule TTP_XOR_MULT_DOSStub_7f5d {
  strings:
    $key_7f5d = { 2b 35 [2] 5f 2d [2] 18 2f [2] 5f 3e [2] 11 32 [2] 1d 38 [2] 0a 33 [2] 11 7d [2] 2c }

  condition:
    any of them
}