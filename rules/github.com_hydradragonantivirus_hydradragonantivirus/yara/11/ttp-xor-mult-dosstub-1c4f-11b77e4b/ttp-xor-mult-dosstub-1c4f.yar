rule TTP_XOR_MULT_DOSStub_1c4f {
  strings:
    $key_1c4f = { 48 27 [2] 3c 3f [2] 7b 3d [2] 3c 2c [2] 72 20 [2] 7e 2a [2] 69 21 [2] 72 6f [2] 4f }

  condition:
    any of them
}