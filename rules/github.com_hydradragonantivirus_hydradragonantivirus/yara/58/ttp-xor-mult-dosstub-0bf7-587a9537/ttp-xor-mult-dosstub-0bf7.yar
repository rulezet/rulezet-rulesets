rule TTP_XOR_MULT_DOSStub_0bf7 {
  strings:
    $key_0bf7 = { 5f 9f [2] 2b 87 [2] 6c 85 [2] 2b 94 [2] 65 98 [2] 69 92 [2] 7e 99 [2] 65 d7 [2] 58 }

  condition:
    any of them
}