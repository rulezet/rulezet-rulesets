rule TTP_XOR_MULT_DOSStub_18f1 {
  strings:
    $key_18f1 = { 4c 99 [2] 38 81 [2] 7f 83 [2] 38 92 [2] 76 9e [2] 7a 94 [2] 6d 9f [2] 76 d1 [2] 4b }

  condition:
    any of them
}