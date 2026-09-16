rule TTP_XOR_MULT_DOSStub_426e {
  strings:
    $key_426e = { 16 06 [2] 62 1e [2] 25 1c [2] 62 0d [2] 2c 01 [2] 20 0b [2] 37 00 [2] 2c 4e [2] 11 }

  condition:
    any of them
}