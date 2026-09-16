rule TTP_XOR_MULT_DOSStub_640d {
  strings:
    $key_640d = { 30 65 [2] 44 7d [2] 03 7f [2] 44 6e [2] 0a 62 [2] 06 68 [2] 11 63 [2] 0a 2d [2] 37 }

  condition:
    any of them
}