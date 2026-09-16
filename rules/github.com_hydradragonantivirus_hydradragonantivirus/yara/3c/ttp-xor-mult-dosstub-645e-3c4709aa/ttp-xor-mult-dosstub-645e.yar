rule TTP_XOR_MULT_DOSStub_645e {
  strings:
    $key_645e = { 30 36 [2] 44 2e [2] 03 2c [2] 44 3d [2] 0a 31 [2] 06 3b [2] 11 30 [2] 0a 7e [2] 37 }

  condition:
    any of them
}