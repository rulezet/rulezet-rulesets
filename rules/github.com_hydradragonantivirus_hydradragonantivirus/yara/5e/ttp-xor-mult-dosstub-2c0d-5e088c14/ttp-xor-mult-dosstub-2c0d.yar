rule TTP_XOR_MULT_DOSStub_2c0d {
  strings:
    $key_2c0d = { 78 65 [2] 0c 7d [2] 4b 7f [2] 0c 6e [2] 42 62 [2] 4e 68 [2] 59 63 [2] 42 2d [2] 7f }

  condition:
    any of them
}