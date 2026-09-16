rule TTP_XOR_MULT_DOSStub_6447 {
  strings:
    $key_6447 = { 30 2f [2] 44 37 [2] 03 35 [2] 44 24 [2] 0a 28 [2] 06 22 [2] 11 29 [2] 0a 67 [2] 37 }

  condition:
    any of them
}