rule TTP_XOR_MULT_DOSStub_134f {
  strings:
    $key_134f = { 47 27 [2] 33 3f [2] 74 3d [2] 33 2c [2] 7d 20 [2] 71 2a [2] 66 21 [2] 7d 6f [2] 40 }

  condition:
    any of them
}