rule TTP_XOR_MULT_DOSStub_515d {
  strings:
    $key_515d = { 05 35 [2] 71 2d [2] 36 2f [2] 71 3e [2] 3f 32 [2] 33 38 [2] 24 33 [2] 3f 7d [2] 02 }

  condition:
    any of them
}