rule TTP_XOR_MULT_DOSStub_745c {
  strings:
    $key_745c = { 20 34 [2] 54 2c [2] 13 2e [2] 54 3f [2] 1a 33 [2] 16 39 [2] 01 32 [2] 1a 7c [2] 27 }

  condition:
    any of them
}