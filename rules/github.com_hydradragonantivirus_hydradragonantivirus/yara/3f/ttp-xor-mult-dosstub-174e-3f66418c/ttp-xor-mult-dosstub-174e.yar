rule TTP_XOR_MULT_DOSStub_174e {
  strings:
    $key_174e = { 43 26 [2] 37 3e [2] 70 3c [2] 37 2d [2] 79 21 [2] 75 2b [2] 62 20 [2] 79 6e [2] 44 }

  condition:
    any of them
}