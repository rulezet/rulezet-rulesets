rule TTP_XOR_MULT_DOSStub_38f7 {
  strings:
    $key_38f7 = { 6c 9f [2] 18 87 [2] 5f 85 [2] 18 94 [2] 56 98 [2] 5a 92 [2] 4d 99 [2] 56 d7 [2] 6b }

  condition:
    any of them
}