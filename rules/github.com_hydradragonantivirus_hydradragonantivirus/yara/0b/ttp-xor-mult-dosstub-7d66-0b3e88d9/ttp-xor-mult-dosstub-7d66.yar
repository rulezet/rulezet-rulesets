rule TTP_XOR_MULT_DOSStub_7d66 {
  strings:
    $key_7d66 = { 29 0e [2] 5d 16 [2] 1a 14 [2] 5d 05 [2] 13 09 [2] 1f 03 [2] 08 08 [2] 13 46 [2] 2e }

  condition:
    any of them
}