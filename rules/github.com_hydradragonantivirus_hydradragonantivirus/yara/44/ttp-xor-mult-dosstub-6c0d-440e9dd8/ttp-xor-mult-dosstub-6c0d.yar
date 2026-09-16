rule TTP_XOR_MULT_DOSStub_6c0d {
  strings:
    $key_6c0d = { 38 65 [2] 4c 7d [2] 0b 7f [2] 4c 6e [2] 02 62 [2] 0e 68 [2] 19 63 [2] 02 2d [2] 3f }

  condition:
    any of them
}