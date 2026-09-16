rule TTP_XOR_MULT_DOSStub_554f {
  strings:
    $key_554f = { 01 27 [2] 75 3f [2] 32 3d [2] 75 2c [2] 3b 20 [2] 37 2a [2] 20 21 [2] 3b 6f [2] 06 }

  condition:
    any of them
}