rule TTP_XOR_MULT_DOSStub_2150 {
  strings:
    $key_2150 = { 75 38 [2] 01 20 [2] 46 22 [2] 01 33 [2] 4f 3f [2] 43 35 [2] 54 3e [2] 4f 70 [2] 72 }

  condition:
    any of them
}