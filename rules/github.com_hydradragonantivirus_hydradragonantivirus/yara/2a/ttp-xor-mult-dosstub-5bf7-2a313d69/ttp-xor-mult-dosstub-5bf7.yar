rule TTP_XOR_MULT_DOSStub_5bf7 {
  strings:
    $key_5bf7 = { 0f 9f [2] 7b 87 [2] 3c 85 [2] 7b 94 [2] 35 98 [2] 39 92 [2] 2e 99 [2] 35 d7 [2] 08 }

  condition:
    any of them
}