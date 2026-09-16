rule TTP_XOR_MULT_DOSStub_4751 {
  strings:
    $key_4751 = { 13 39 [2] 67 21 [2] 20 23 [2] 67 32 [2] 29 3e [2] 25 34 [2] 32 3f [2] 29 71 [2] 14 }

  condition:
    any of them
}