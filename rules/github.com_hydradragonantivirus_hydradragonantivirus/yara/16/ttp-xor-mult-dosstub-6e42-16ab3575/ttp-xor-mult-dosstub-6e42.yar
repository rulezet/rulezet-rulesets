rule TTP_XOR_MULT_DOSStub_6e42 {
  strings:
    $key_6e42 = { 3a 2a [2] 4e 32 [2] 09 30 [2] 4e 21 [2] 00 2d [2] 0c 27 [2] 1b 2c [2] 00 62 [2] 3d }

  condition:
    any of them
}