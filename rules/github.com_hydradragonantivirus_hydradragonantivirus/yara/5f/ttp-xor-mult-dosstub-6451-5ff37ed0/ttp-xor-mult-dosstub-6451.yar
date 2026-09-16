rule TTP_XOR_MULT_DOSStub_6451 {
  strings:
    $key_6451 = { 30 39 [2] 44 21 [2] 03 23 [2] 44 32 [2] 0a 3e [2] 06 34 [2] 11 3f [2] 0a 71 [2] 37 }

  condition:
    any of them
}