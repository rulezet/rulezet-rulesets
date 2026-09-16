rule TTP_XOR_MULT_DOSStub_4f5e {
  strings:
    $key_4f5e = { 1b 36 [2] 6f 2e [2] 28 2c [2] 6f 3d [2] 21 31 [2] 2d 3b [2] 3a 30 [2] 21 7e [2] 1c }

  condition:
    any of them
}