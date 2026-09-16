rule TTP_XOR_MULT_DOSStub_1d4f {
  strings:
    $key_1d4f = { 49 27 [2] 3d 3f [2] 7a 3d [2] 3d 2c [2] 73 20 [2] 7f 2a [2] 68 21 [2] 73 6f [2] 4e }

  condition:
    any of them
}