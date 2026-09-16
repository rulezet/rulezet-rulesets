rule TTP_XOR_MULT_DOSStub_485d {
  strings:
    $key_485d = { 1c 35 [2] 68 2d [2] 2f 2f [2] 68 3e [2] 26 32 [2] 2a 38 [2] 3d 33 [2] 26 7d [2] 1b }

  condition:
    any of them
}