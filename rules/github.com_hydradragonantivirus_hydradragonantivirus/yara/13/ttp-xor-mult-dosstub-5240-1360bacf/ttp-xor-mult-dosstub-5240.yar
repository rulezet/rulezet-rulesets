rule TTP_XOR_MULT_DOSStub_5240 {
  strings:
    $key_5240 = { 06 28 [2] 72 30 [2] 35 32 [2] 72 23 [2] 3c 2f [2] 30 25 [2] 27 2e [2] 3c 60 [2] 01 }

  condition:
    any of them
}