rule TTP_XOR_MULT_DOSStub_0d4f {
  strings:
    $key_0d4f = { 59 27 [2] 2d 3f [2] 6a 3d [2] 2d 2c [2] 63 20 [2] 6f 2a [2] 78 21 [2] 63 6f [2] 5e }

  condition:
    any of them
}