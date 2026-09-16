rule TTP_XOR_MULT_DOSStub_5260 {
  strings:
    $key_5260 = { 06 08 [2] 72 10 [2] 35 12 [2] 72 03 [2] 3c 0f [2] 30 05 [2] 27 0e [2] 3c 40 [2] 01 }

  condition:
    any of them
}