rule TTP_XOR_MULT_DOSStub_6e4f {
  strings:
    $key_6e4f = { 3a 27 [2] 4e 3f [2] 09 3d [2] 4e 2c [2] 00 20 [2] 0c 2a [2] 1b 21 [2] 00 6f [2] 3d }

  condition:
    any of them
}