rule TTP_XOR_MULT_DOSStub_7f0d {
  strings:
    $key_7f0d = { 2b 65 [2] 5f 7d [2] 18 7f [2] 5f 6e [2] 11 62 [2] 1d 68 [2] 0a 63 [2] 11 2d [2] 2c }

  condition:
    any of them
}