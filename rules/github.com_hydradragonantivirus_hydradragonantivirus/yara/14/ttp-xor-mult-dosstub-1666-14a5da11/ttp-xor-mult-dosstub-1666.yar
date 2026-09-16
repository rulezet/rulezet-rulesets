rule TTP_XOR_MULT_DOSStub_1666 {
  strings:
    $key_1666 = { 42 0e [2] 36 16 [2] 71 14 [2] 36 05 [2] 78 09 [2] 74 03 [2] 63 08 [2] 78 46 [2] 45 }

  condition:
    any of them
}