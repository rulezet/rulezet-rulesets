rule TTP_XOR_MULT_DOSStub_7f52 {
  strings:
    $key_7f52 = { 2b 3a [2] 5f 22 [2] 18 20 [2] 5f 31 [2] 11 3d [2] 1d 37 [2] 0a 3c [2] 11 72 [2] 2c }

  condition:
    any of them
}