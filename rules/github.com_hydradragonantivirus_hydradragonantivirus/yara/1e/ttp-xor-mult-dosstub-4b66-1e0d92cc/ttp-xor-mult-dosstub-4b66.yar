rule TTP_XOR_MULT_DOSStub_4b66 {
  strings:
    $key_4b66 = { 1f 0e [2] 6b 16 [2] 2c 14 [2] 6b 05 [2] 25 09 [2] 29 03 [2] 3e 08 [2] 25 46 [2] 18 }

  condition:
    any of them
}