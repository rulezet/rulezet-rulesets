rule TTP_XOR_MULT_DOSStub_535e {
  strings:
    $key_535e = { 07 36 [2] 73 2e [2] 34 2c [2] 73 3d [2] 3d 31 [2] 31 3b [2] 26 30 [2] 3d 7e [2] 00 }

  condition:
    any of them
}