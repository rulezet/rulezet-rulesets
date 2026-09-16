rule TTP_XOR_MULT_DOSStub_7a4f {
  strings:
    $key_7a4f = { 2e 27 [2] 5a 3f [2] 1d 3d [2] 5a 2c [2] 14 20 [2] 18 2a [2] 0f 21 [2] 14 6f [2] 29 }

  condition:
    any of them
}