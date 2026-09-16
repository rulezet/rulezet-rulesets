rule TTP_XOR_MULT_DOSStub_6450 {
  strings:
    $key_6450 = { 30 38 [2] 44 20 [2] 03 22 [2] 44 33 [2] 0a 3f [2] 06 35 [2] 11 3e [2] 0a 70 [2] 37 }

  condition:
    any of them
}