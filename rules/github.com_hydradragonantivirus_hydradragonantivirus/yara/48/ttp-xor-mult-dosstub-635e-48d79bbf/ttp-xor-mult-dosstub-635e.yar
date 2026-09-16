rule TTP_XOR_MULT_DOSStub_635e {
  strings:
    $key_635e = { 37 36 [2] 43 2e [2] 04 2c [2] 43 3d [2] 0d 31 [2] 01 3b [2] 16 30 [2] 0d 7e [2] 30 }

  condition:
    any of them
}