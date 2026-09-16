rule TTP_XOR_MULT_DOSStub_1a66 {
  strings:
    $key_1a66 = { 4e 0e [2] 3a 16 [2] 7d 14 [2] 3a 05 [2] 74 09 [2] 78 03 [2] 6f 08 [2] 74 46 [2] 49 }

  condition:
    any of them
}