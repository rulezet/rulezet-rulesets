rule TTP_XOR_MULT_DOSStub_524f {
  strings:
    $key_524f = { 06 27 [2] 72 3f [2] 35 3d [2] 72 2c [2] 3c 20 [2] 30 2a [2] 27 21 [2] 3c 6f [2] 01 }

  condition:
    any of them
}