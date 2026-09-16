rule TTP_XOR_MULT_DOSStub_435e {
  strings:
    $key_435e = { 17 36 [2] 63 2e [2] 24 2c [2] 63 3d [2] 2d 31 [2] 21 3b [2] 36 30 [2] 2d 7e [2] 10 }

  condition:
    any of them
}