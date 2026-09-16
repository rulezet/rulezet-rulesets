rule TTP_XOR_MULT_DOSStub_235e {
  strings:
    $key_235e = { 77 36 [2] 03 2e [2] 44 2c [2] 03 3d [2] 4d 31 [2] 41 3b [2] 56 30 [2] 4d 7e [2] 70 }

  condition:
    any of them
}