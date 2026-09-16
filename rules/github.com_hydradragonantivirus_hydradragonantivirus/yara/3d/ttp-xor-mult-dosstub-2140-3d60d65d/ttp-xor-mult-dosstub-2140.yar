rule TTP_XOR_MULT_DOSStub_2140 {
  strings:
    $key_2140 = { 75 28 [2] 01 30 [2] 46 32 [2] 01 23 [2] 4f 2f [2] 43 25 [2] 54 2e [2] 4f 60 [2] 72 }

  condition:
    any of them
}