rule TTP_XOR_MULT_DOSStub_0066 {
  strings:
    $key_0066 = { 54 0e [2] 20 16 [2] 67 14 [2] 20 05 [2] 6e 09 [2] 62 03 [2] 75 08 [2] 6e 46 [2] 53 }

  condition:
    any of them
}