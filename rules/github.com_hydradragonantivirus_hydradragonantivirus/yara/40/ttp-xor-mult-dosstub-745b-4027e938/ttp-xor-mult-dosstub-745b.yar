rule TTP_XOR_MULT_DOSStub_745b {
  strings:
    $key_745b = { 20 33 [2] 54 2b [2] 13 29 [2] 54 38 [2] 1a 34 [2] 16 3e [2] 01 35 [2] 1a 7b [2] 27 }

  condition:
    any of them
}