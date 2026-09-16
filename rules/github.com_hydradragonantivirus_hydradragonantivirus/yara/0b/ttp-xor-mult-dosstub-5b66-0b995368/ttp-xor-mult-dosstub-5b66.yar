rule TTP_XOR_MULT_DOSStub_5b66 {
  strings:
    $key_5b66 = { 0f 0e [2] 7b 16 [2] 3c 14 [2] 7b 05 [2] 35 09 [2] 39 03 [2] 2e 08 [2] 35 46 [2] 08 }

  condition:
    any of them
}