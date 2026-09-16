rule TTP_XOR_MULT_DOSStub_366e {
  strings:
    $key_366e = { 62 06 [2] 16 1e [2] 51 1c [2] 16 0d [2] 58 01 [2] 54 0b [2] 43 00 [2] 58 4e [2] 65 }

  condition:
    any of them
}