rule TTP_XOR_MULT_DOSStub_465e {
  strings:
    $key_465e = { 12 36 [2] 66 2e [2] 21 2c [2] 66 3d [2] 28 31 [2] 24 3b [2] 33 30 [2] 28 7e [2] 15 }

  condition:
    any of them
}