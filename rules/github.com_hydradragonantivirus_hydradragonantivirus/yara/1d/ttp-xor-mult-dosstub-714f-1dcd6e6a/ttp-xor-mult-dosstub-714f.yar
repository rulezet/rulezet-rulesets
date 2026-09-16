rule TTP_XOR_MULT_DOSStub_714f {
  strings:
    $key_714f = { 25 27 [2] 51 3f [2] 16 3d [2] 51 2c [2] 1f 20 [2] 13 2a [2] 04 21 [2] 1f 6f [2] 22 }

  condition:
    any of them
}