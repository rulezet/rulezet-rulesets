rule TTP_XOR_MULT_DOSStub_5d5e {
  strings:
    $key_5d5e = { 09 36 [2] 7d 2e [2] 3a 2c [2] 7d 3d [2] 33 31 [2] 3f 3b [2] 28 30 [2] 33 7e [2] 0e }

  condition:
    any of them
}