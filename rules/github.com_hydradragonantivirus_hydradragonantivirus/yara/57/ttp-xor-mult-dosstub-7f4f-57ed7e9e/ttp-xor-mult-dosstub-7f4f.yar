rule TTP_XOR_MULT_DOSStub_7f4f {
  strings:
    $key_7f4f = { 2b 27 [2] 5f 3f [2] 18 3d [2] 5f 2c [2] 11 20 [2] 1d 2a [2] 0a 21 [2] 11 6f [2] 2c }

  condition:
    any of them
}