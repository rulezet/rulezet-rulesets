rule TTP_XOR_MULT_DOSStub_745d {
  strings:
    $key_745d = { 20 35 [2] 54 2d [2] 13 2f [2] 54 3e [2] 1a 32 [2] 16 38 [2] 01 33 [2] 1a 7d [2] 27 }

  condition:
    any of them
}