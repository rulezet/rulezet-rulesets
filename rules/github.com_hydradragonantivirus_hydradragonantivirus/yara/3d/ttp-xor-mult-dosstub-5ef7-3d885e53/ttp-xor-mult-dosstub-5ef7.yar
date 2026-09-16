rule TTP_XOR_MULT_DOSStub_5ef7 {
  strings:
    $key_5ef7 = { 0a 9f [2] 7e 87 [2] 39 85 [2] 7e 94 [2] 30 98 [2] 3c 92 [2] 2b 99 [2] 30 d7 [2] 0d }

  condition:
    any of them
}