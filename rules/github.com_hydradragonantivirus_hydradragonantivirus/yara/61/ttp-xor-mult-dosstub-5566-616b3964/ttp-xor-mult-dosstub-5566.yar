rule TTP_XOR_MULT_DOSStub_5566 {
  strings:
    $key_5566 = { 01 0e [2] 75 16 [2] 32 14 [2] 75 05 [2] 3b 09 [2] 37 03 [2] 20 08 [2] 3b 46 [2] 06 }

  condition:
    any of them
}