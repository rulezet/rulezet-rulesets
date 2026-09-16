rule TTP_XOR_MULT_DOSStub_6c4f {
  strings:
    $key_6c4f = { 38 27 [2] 4c 3f [2] 0b 3d [2] 4c 2c [2] 02 20 [2] 0e 2a [2] 19 21 [2] 02 6f [2] 3f }

  condition:
    any of them
}