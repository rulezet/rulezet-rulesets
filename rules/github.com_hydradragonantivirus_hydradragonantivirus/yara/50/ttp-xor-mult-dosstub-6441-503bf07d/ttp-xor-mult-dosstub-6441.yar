rule TTP_XOR_MULT_DOSStub_6441 {
  strings:
    $key_6441 = { 30 29 [2] 44 31 [2] 03 33 [2] 44 22 [2] 0a 2e [2] 06 24 [2] 11 2f [2] 0a 61 [2] 37 }

  condition:
    any of them
}