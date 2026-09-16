rule TTP_XOR_MULT_DOSStub_745f {
  strings:
    $key_745f = { 20 37 [2] 54 2f [2] 13 2d [2] 54 3c [2] 1a 30 [2] 16 3a [2] 01 31 [2] 1a 7f [2] 27 }

  condition:
    any of them
}