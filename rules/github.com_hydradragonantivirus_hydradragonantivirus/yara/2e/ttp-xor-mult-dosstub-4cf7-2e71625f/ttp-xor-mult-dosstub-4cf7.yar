rule TTP_XOR_MULT_DOSStub_4cf7 {
  strings:
    $key_4cf7 = { 18 9f [2] 6c 87 [2] 2b 85 [2] 6c 94 [2] 22 98 [2] 2e 92 [2] 39 99 [2] 22 d7 [2] 1f }

  condition:
    any of them
}