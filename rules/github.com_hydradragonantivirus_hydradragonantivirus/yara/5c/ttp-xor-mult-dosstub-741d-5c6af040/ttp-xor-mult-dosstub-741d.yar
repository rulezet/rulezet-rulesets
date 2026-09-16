rule TTP_XOR_MULT_DOSStub_741d {
  strings:
    $key_741d = { 20 75 [2] 54 6d [2] 13 6f [2] 54 7e [2] 1a 72 [2] 16 78 [2] 01 73 [2] 1a 3d [2] 27 }

  condition:
    any of them
}