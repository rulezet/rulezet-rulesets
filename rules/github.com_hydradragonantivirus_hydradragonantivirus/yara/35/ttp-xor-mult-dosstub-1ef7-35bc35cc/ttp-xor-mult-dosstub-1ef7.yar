rule TTP_XOR_MULT_DOSStub_1ef7 {
  strings:
    $key_1ef7 = { 4a 9f [2] 3e 87 [2] 79 85 [2] 3e 94 [2] 70 98 [2] 7c 92 [2] 6b 99 [2] 70 d7 [2] 4d }

  condition:
    any of them
}