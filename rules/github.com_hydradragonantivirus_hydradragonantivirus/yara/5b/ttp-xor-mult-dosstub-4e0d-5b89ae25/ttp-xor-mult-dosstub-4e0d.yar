rule TTP_XOR_MULT_DOSStub_4e0d {
  strings:
    $key_4e0d = { 1a 65 [2] 6e 7d [2] 29 7f [2] 6e 6e [2] 20 62 [2] 2c 68 [2] 3b 63 [2] 20 2d [2] 1d }

  condition:
    any of them
}