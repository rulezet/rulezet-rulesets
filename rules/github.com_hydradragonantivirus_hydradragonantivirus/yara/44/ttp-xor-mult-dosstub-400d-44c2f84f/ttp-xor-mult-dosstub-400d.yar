rule TTP_XOR_MULT_DOSStub_400d {
  strings:
    $key_400d = { 14 65 [2] 60 7d [2] 27 7f [2] 60 6e [2] 2e 62 [2] 22 68 [2] 35 63 [2] 2e 2d [2] 13 }

  condition:
    any of them
}