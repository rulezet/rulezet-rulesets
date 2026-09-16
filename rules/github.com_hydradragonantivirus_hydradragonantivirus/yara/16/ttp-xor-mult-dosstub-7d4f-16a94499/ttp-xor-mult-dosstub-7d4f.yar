rule TTP_XOR_MULT_DOSStub_7d4f {
  strings:
    $key_7d4f = { 29 27 [2] 5d 3f [2] 1a 3d [2] 5d 2c [2] 13 20 [2] 1f 2a [2] 08 21 [2] 13 6f [2] 2e }

  condition:
    any of them
}