rule TTP_XOR_MULT_DOSStub_6d4f {
  strings:
    $key_6d4f = { 39 27 [2] 4d 3f [2] 0a 3d [2] 4d 2c [2] 03 20 [2] 0f 2a [2] 18 21 [2] 03 6f [2] 3e }

  condition:
    any of them
}