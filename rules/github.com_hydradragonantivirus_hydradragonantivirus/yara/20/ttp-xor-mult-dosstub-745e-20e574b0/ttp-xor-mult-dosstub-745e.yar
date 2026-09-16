rule TTP_XOR_MULT_DOSStub_745e {
  strings:
    $key_745e = { 20 36 [2] 54 2e [2] 13 2c [2] 54 3d [2] 1a 31 [2] 16 3b [2] 01 30 [2] 1a 7e [2] 27 }

  condition:
    any of them
}