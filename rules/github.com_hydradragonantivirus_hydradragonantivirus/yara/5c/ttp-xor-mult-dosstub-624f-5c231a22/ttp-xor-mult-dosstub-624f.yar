rule TTP_XOR_MULT_DOSStub_624f {
  strings:
    $key_624f = { 36 27 [2] 42 3f [2] 05 3d [2] 42 2c [2] 0c 20 [2] 00 2a [2] 17 21 [2] 0c 6f [2] 31 }

  condition:
    any of them
}