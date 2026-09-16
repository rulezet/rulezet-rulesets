rule TTP_XOR_MULT_DOSStub_72f1 {
  strings:
    $key_72f1 = { 26 99 [2] 52 81 [2] 15 83 [2] 52 92 [2] 1c 9e [2] 10 94 [2] 07 9f [2] 1c d1 [2] 21 }

  condition:
    any of them
}