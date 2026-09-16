rule TTP_XOR_MULT_DOSStub_4d4f {
  strings:
    $key_4d4f = { 19 27 [2] 6d 3f [2] 2a 3d [2] 6d 2c [2] 23 20 [2] 2f 2a [2] 38 21 [2] 23 6f [2] 1e }

  condition:
    any of them
}