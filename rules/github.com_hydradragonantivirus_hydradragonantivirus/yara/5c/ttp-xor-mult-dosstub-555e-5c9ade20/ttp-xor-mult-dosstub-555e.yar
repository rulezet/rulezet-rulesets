rule TTP_XOR_MULT_DOSStub_555e {
  strings:
    $key_555e = { 01 36 [2] 75 2e [2] 32 2c [2] 75 3d [2] 3b 31 [2] 37 3b [2] 20 30 [2] 3b 7e [2] 06 }

  condition:
    any of them
}