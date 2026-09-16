rule TTP_XOR_MULT_DOSStub_5526 {
  strings:
    $key_5526 = { 01 4e [2] 75 56 [2] 32 54 [2] 75 45 [2] 3b 49 [2] 37 43 [2] 20 48 [2] 3b 06 [2] 06 }

  condition:
    any of them
}