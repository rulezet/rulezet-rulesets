rule TTP_XOR_MULT_DOSStub_176e {
  strings:
    $key_176e = { 43 06 [2] 37 1e [2] 70 1c [2] 37 0d [2] 79 01 [2] 75 0b [2] 62 00 [2] 79 4e [2] 44 }

  condition:
    any of them
}