rule TTP_XOR_MULT_DOSStub_4a5e {
  strings:
    $key_4a5e = { 1e 36 [2] 6a 2e [2] 2d 2c [2] 6a 3d [2] 24 31 [2] 28 3b [2] 3f 30 [2] 24 7e [2] 19 }

  condition:
    any of them
}