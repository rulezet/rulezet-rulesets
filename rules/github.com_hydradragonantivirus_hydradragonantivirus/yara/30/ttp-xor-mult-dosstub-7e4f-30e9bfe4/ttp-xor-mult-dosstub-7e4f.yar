rule TTP_XOR_MULT_DOSStub_7e4f {
  strings:
    $key_7e4f = { 2a 27 [2] 5e 3f [2] 19 3d [2] 5e 2c [2] 10 20 [2] 1c 2a [2] 0b 21 [2] 10 6f [2] 2d }

  condition:
    any of them
}