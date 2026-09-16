rule TTP_XOR_MULT_DOSStub_3ef7 {
  strings:
    $key_3ef7 = { 6a 9f [2] 1e 87 [2] 59 85 [2] 1e 94 [2] 50 98 [2] 5c 92 [2] 4b 99 [2] 50 d7 [2] 6d }

  condition:
    any of them
}