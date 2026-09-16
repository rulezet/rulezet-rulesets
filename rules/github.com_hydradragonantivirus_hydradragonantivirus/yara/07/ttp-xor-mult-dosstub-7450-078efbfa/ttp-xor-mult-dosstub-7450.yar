rule TTP_XOR_MULT_DOSStub_7450 {
  strings:
    $key_7450 = { 20 38 [2] 54 20 [2] 13 22 [2] 54 33 [2] 1a 3f [2] 16 35 [2] 01 3e [2] 1a 70 [2] 27 }

  condition:
    any of them
}