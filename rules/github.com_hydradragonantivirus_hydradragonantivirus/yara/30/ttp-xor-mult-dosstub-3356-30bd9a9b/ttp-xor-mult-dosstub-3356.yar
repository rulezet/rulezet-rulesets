rule TTP_XOR_MULT_DOSStub_3356 {
  strings:
    $key_3356 = { 67 3e [2] 13 26 [2] 54 24 [2] 13 35 [2] 5d 39 [2] 51 33 [2] 46 38 [2] 5d 76 [2] 60 }

  condition:
    any of them
}