rule TTP_XOR_MULT_DOSStub_7252 {
  strings:
    $key_7252 = { 26 3a [2] 52 22 [2] 15 20 [2] 52 31 [2] 1c 3d [2] 10 37 [2] 07 3c [2] 1c 72 [2] 21 }

  condition:
    any of them
}