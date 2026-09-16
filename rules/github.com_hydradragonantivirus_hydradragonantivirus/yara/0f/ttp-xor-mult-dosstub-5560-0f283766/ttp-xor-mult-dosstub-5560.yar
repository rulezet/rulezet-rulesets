rule TTP_XOR_MULT_DOSStub_5560 {
  strings:
    $key_5560 = { 01 08 [2] 75 10 [2] 32 12 [2] 75 03 [2] 3b 0f [2] 37 05 [2] 20 0e [2] 3b 40 [2] 06 }

  condition:
    any of them
}