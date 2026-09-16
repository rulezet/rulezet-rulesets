rule TTP_XOR_MULT_DOSStub_5a5d {
  strings:
    $key_5a5d = { 0e 35 [2] 7a 2d [2] 3d 2f [2] 7a 3e [2] 34 32 [2] 38 38 [2] 2f 33 [2] 34 7d [2] 09 }

  condition:
    any of them
}