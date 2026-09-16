rule TTP_XOR_MULT_DOSStub_782e {
  strings:
    $key_782e = { 2c 46 [2] 58 5e [2] 1f 5c [2] 58 4d [2] 16 41 [2] 1a 4b [2] 0d 40 [2] 16 0e [2] 2b }

  condition:
    any of them
}