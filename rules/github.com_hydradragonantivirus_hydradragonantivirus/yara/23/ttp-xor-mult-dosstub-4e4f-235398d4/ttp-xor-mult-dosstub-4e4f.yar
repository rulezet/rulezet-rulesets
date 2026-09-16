rule TTP_XOR_MULT_DOSStub_4e4f {
  strings:
    $key_4e4f = { 1a 27 [2] 6e 3f [2] 29 3d [2] 6e 2c [2] 20 20 [2] 2c 2a [2] 3b 21 [2] 20 6f [2] 1d }

  condition:
    any of them
}