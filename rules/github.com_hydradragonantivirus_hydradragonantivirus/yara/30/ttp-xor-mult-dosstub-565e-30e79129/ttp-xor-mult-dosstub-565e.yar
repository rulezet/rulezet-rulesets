rule TTP_XOR_MULT_DOSStub_565e {
  strings:
    $key_565e = { 02 36 [2] 76 2e [2] 31 2c [2] 76 3d [2] 38 31 [2] 34 3b [2] 23 30 [2] 38 7e [2] 05 }

  condition:
    any of them
}