rule TTP_XOR_MULT_DOSStub_0ef7 {
  strings:
    $key_0ef7 = { 5a 9f [2] 2e 87 [2] 69 85 [2] 2e 94 [2] 60 98 [2] 6c 92 [2] 7b 99 [2] 60 d7 [2] 5d }

  condition:
    any of them
}