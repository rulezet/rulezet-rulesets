rule TTP_XOR_MULT_DOSStub_1266 {
  strings:
    $key_1266 = { 46 0e [2] 32 16 [2] 75 14 [2] 32 05 [2] 7c 09 [2] 70 03 [2] 67 08 [2] 7c 46 [2] 41 }

  condition:
    any of them
}