rule TTP_XOR_MULT_DOSStub_6666 {
  strings:
    $key_6666 = { 32 0e [2] 46 16 [2] 01 14 [2] 46 05 [2] 08 09 [2] 04 03 [2] 13 08 [2] 08 46 [2] 35 }

  condition:
    any of them
}