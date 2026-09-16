rule TTP_XOR_MULT_DOSStub_384f {
  strings:
    $key_384f = { 6c 27 [2] 18 3f [2] 5f 3d [2] 18 2c [2] 56 20 [2] 5a 2a [2] 4d 21 [2] 56 6f [2] 6b }

  condition:
    any of them
}