rule TTP_XOR_MULT_DOSStub_5571 {
  strings:
    $key_5571 = { 01 19 [2] 75 01 [2] 32 03 [2] 75 12 [2] 3b 1e [2] 37 14 [2] 20 1f [2] 3b 51 [2] 06 }

  condition:
    any of them
}