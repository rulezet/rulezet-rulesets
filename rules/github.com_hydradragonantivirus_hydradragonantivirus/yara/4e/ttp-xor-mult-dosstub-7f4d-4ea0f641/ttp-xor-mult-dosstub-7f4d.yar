rule TTP_XOR_MULT_DOSStub_7f4d {
  strings:
    $key_7f4d = { 2b 25 [2] 5f 3d [2] 18 3f [2] 5f 2e [2] 11 22 [2] 1d 28 [2] 0a 23 [2] 11 6d [2] 2c }

  condition:
    any of them
}