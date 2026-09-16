rule TTP_XOR_MULT_DOSStub_6766 {
  strings:
    $key_6766 = { 33 0e [2] 47 16 [2] 00 14 [2] 47 05 [2] 09 09 [2] 05 03 [2] 12 08 [2] 09 46 [2] 34 }

  condition:
    any of them
}