rule TTP_XOR_MULT_DOSStub_2d66 {
  strings:
    $key_2d66 = { 79 0e [2] 0d 16 [2] 4a 14 [2] 0d 05 [2] 43 09 [2] 4f 03 [2] 58 08 [2] 43 46 [2] 7e }

  condition:
    any of them
}