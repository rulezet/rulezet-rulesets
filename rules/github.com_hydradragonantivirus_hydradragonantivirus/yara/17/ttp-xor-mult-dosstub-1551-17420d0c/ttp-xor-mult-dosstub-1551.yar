rule TTP_XOR_MULT_DOSStub_1551 {
  strings:
    $key_1551 = { 41 39 [2] 35 21 [2] 72 23 [2] 35 32 [2] 7b 3e [2] 77 34 [2] 60 3f [2] 7b 71 [2] 46 }

  condition:
    any of them
}