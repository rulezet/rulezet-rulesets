rule TTP_XOR_MULT_DOSStub_5a5e {
  strings:
    $key_5a5e = { 0e 36 [2] 7a 2e [2] 3d 2c [2] 7a 3d [2] 34 31 [2] 38 3b [2] 2f 30 [2] 34 7e [2] 09 }

  condition:
    any of them
}