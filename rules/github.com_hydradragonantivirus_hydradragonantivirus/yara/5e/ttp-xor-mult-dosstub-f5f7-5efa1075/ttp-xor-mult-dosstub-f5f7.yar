rule TTP_XOR_MULT_DOSStub_f5f7 {
  strings:
    $key_f5f7 = { a1 9f [2] d5 87 [2] 92 85 [2] d5 94 [2] 9b 98 [2] 97 92 [2] 80 99 [2] 9b d7 [2] a6 }

  condition:
    any of them
}