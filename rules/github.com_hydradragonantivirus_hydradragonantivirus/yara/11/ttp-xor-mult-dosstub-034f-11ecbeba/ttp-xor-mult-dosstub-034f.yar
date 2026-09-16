rule TTP_XOR_MULT_DOSStub_034f {
  strings:
    $key_034f = { 57 27 [2] 23 3f [2] 64 3d [2] 23 2c [2] 6d 20 [2] 61 2a [2] 76 21 [2] 6d 6f [2] 50 }

  condition:
    any of them
}