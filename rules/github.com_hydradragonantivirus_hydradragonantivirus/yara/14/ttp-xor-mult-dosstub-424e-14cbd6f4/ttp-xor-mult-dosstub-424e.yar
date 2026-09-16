rule TTP_XOR_MULT_DOSStub_424e {
  strings:
    $key_424e = { 16 26 [2] 62 3e [2] 25 3c [2] 62 2d [2] 2c 21 [2] 20 2b [2] 37 20 [2] 2c 6e [2] 11 }

  condition:
    any of them
}