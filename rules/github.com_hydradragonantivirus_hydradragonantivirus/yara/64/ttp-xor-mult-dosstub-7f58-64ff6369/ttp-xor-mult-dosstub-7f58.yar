rule TTP_XOR_MULT_DOSStub_7f58 {
  strings:
    $key_7f58 = { 2b 30 [2] 5f 28 [2] 18 2a [2] 5f 3b [2] 11 37 [2] 1d 3d [2] 0a 36 [2] 11 78 [2] 2c }

  condition:
    any of them
}