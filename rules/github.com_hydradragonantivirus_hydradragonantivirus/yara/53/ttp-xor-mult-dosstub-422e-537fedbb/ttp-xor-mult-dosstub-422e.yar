rule TTP_XOR_MULT_DOSStub_422e {
  strings:
    $key_422e = { 16 46 [2] 62 5e [2] 25 5c [2] 62 4d [2] 2c 41 [2] 20 4b [2] 37 40 [2] 2c 0e [2] 11 }

  condition:
    any of them
}