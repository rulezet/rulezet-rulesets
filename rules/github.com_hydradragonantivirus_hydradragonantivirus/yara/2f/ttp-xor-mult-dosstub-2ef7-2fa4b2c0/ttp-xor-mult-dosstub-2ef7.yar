rule TTP_XOR_MULT_DOSStub_2ef7 {
  strings:
    $key_2ef7 = { 7a 9f [2] 0e 87 [2] 49 85 [2] 0e 94 [2] 40 98 [2] 4c 92 [2] 5b 99 [2] 40 d7 [2] 7d }

  condition:
    any of them
}