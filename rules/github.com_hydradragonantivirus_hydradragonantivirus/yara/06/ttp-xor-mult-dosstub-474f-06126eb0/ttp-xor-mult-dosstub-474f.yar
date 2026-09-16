rule TTP_XOR_MULT_DOSStub_474f {
  strings:
    $key_474f = { 13 27 [2] 67 3f [2] 20 3d [2] 67 2c [2] 29 20 [2] 25 2a [2] 32 21 [2] 29 6f [2] 14 }

  condition:
    any of them
}