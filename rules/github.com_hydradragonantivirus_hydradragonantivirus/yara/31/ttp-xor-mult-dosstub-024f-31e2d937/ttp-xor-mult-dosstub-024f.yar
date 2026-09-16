rule TTP_XOR_MULT_DOSStub_024f {
  strings:
    $key_024f = { 56 27 [2] 22 3f [2] 65 3d [2] 22 2c [2] 6c 20 [2] 60 2a [2] 77 21 [2] 6c 6f [2] 51 }

  condition:
    any of them
}