rule TTP_XOR_MULT_DOSStub_3d42 {
  strings:
    $key_3d42 = { 69 2a [2] 1d 32 [2] 5a 30 [2] 1d 21 [2] 53 2d [2] 5f 27 [2] 48 2c [2] 53 62 [2] 6e }

  condition:
    any of them
}