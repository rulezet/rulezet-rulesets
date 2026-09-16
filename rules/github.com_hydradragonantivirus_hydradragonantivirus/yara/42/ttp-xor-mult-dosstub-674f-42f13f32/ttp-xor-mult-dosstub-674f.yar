rule TTP_XOR_MULT_DOSStub_674f {
  strings:
    $key_674f = { 33 27 [2] 47 3f [2] 00 3d [2] 47 2c [2] 09 20 [2] 05 2a [2] 12 21 [2] 09 6f [2] 34 }

  condition:
    any of them
}