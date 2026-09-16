rule TTP_XOR_MULT_DOSStub_2156 {
  strings:
    $key_2156 = { 75 3e [2] 01 26 [2] 46 24 [2] 01 35 [2] 4f 39 [2] 43 33 [2] 54 38 [2] 4f 76 [2] 72 }

  condition:
    any of them
}