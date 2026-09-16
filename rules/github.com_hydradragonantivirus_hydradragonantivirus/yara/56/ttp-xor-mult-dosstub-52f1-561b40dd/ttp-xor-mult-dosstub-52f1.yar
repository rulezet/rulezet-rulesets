rule TTP_XOR_MULT_DOSStub_52f1 {
  strings:
    $key_52f1 = { 06 99 [2] 72 81 [2] 35 83 [2] 72 92 [2] 3c 9e [2] 30 94 [2] 27 9f [2] 3c d1 [2] 01 }

  condition:
    any of them
}