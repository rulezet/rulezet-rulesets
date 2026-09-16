rule TTP_XOR_MULT_DOSStub_084f {
  strings:
    $key_084f = { 5c 27 [2] 28 3f [2] 6f 3d [2] 28 2c [2] 66 20 [2] 6a 2a [2] 7d 21 [2] 66 6f [2] 5b }

  condition:
    any of them
}