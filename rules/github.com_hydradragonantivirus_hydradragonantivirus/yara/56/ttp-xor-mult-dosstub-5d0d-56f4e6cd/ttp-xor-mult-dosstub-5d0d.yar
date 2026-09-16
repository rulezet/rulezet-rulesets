rule TTP_XOR_MULT_DOSStub_5d0d {
  strings:
    $key_5d0d = { 09 65 [2] 7d 7d [2] 3a 7f [2] 7d 6e [2] 33 62 [2] 3f 68 [2] 28 63 [2] 33 2d [2] 0e }

  condition:
    any of them
}