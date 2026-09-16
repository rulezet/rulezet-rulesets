rule TTP_XOR_MULT_DOSStub_5250 {
  strings:
    $key_5250 = { 06 38 [2] 72 20 [2] 35 22 [2] 72 33 [2] 3c 3f [2] 30 35 [2] 27 3e [2] 3c 70 [2] 01 }

  condition:
    any of them
}