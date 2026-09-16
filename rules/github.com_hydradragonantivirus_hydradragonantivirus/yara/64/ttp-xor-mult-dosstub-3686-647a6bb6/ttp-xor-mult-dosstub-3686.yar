rule TTP_XOR_MULT_DOSStub_3686 {
  strings:
    $key_3686 = { 62 ee [2] 16 f6 [2] 51 f4 [2] 16 e5 [2] 58 e9 [2] 54 e3 [2] 43 e8 [2] 58 a6 [2] 65 }

  condition:
    any of them
}