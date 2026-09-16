rule TTP_XOR_MULT_DOSStub_780d {
  strings:
    $key_780d = { 2c 65 [2] 58 7d [2] 1f 7f [2] 58 6e [2] 16 62 [2] 1a 68 [2] 0d 63 [2] 16 2d [2] 2b }

  condition:
    any of them
}