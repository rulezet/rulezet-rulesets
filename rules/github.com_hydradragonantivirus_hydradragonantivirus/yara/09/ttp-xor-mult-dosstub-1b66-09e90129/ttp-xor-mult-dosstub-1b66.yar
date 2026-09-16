rule TTP_XOR_MULT_DOSStub_1b66 {
  strings:
    $key_1b66 = { 4f 0e [2] 3b 16 [2] 7c 14 [2] 3b 05 [2] 75 09 [2] 79 03 [2] 6e 08 [2] 75 46 [2] 48 }

  condition:
    any of them
}