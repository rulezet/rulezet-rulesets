rule TTP_XOR_MULT_DOSStub_3df7 {
  strings:
    $key_3df7 = { 69 9f [2] 1d 87 [2] 5a 85 [2] 1d 94 [2] 53 98 [2] 5f 92 [2] 48 99 [2] 53 d7 [2] 6e }

  condition:
    any of them
}