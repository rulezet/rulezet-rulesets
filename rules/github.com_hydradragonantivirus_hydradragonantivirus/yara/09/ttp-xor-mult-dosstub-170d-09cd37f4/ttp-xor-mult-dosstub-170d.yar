rule TTP_XOR_MULT_DOSStub_170d {
  strings:
    $key_170d = { 43 65 [2] 37 7d [2] 70 7f [2] 37 6e [2] 79 62 [2] 75 68 [2] 62 63 [2] 79 2d [2] 44 }

  condition:
    any of them
}