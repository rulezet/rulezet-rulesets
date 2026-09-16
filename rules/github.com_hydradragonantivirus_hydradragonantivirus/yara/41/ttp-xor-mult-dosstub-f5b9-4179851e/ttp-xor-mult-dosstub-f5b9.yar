rule TTP_XOR_MULT_DOSStub_f5b9 {
  strings:
    $key_f5b9 = { a1 d1 [2] d5 c9 [2] 92 cb [2] d5 da [2] 9b d6 [2] 97 dc [2] 80 d7 [2] 9b 99 [2] a6 }

  condition:
    any of them
}