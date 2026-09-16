rule TTP_XOR_MULT_DOSStub_5a0d {
  strings:
    $key_5a0d = { 0e 65 [2] 7a 7d [2] 3d 7f [2] 7a 6e [2] 34 62 [2] 38 68 [2] 2f 63 [2] 34 2d [2] 09 }

  condition:
    any of them
}