rule TTP_XOR_MULT_DOSStub_634f {
  strings:
    $key_634f = { 37 27 [2] 43 3f [2] 04 3d [2] 43 2c [2] 0d 20 [2] 01 2a [2] 16 21 [2] 0d 6f [2] 30 }

  condition:
    any of them
}