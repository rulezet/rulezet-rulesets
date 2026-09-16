rule TTP_XOR_MULT_DOSStub_394f {
  strings:
    $key_394f = { 6d 27 [2] 19 3f [2] 5e 3d [2] 19 2c [2] 57 20 [2] 5b 2a [2] 4c 21 [2] 57 6f [2] 6a }

  condition:
    any of them
}