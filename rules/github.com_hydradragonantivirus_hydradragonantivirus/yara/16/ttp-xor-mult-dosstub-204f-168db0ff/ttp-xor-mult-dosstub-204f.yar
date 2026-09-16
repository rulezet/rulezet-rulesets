rule TTP_XOR_MULT_DOSStub_204f {
  strings:
    $key_204f = { 74 27 [2] 00 3f [2] 47 3d [2] 00 2c [2] 4e 20 [2] 42 2a [2] 55 21 [2] 4e 6f [2] 73 }

  condition:
    any of them
}