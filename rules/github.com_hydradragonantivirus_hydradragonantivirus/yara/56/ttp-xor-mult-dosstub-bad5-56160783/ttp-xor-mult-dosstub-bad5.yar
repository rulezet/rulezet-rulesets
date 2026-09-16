rule TTP_XOR_MULT_DOSStub_bad5 {
  strings:
    $key_bad5 = { ee bd [2] 9a a5 [2] dd a7 [2] 9a b6 [2] d4 ba [2] d8 b0 [2] cf bb [2] d4 f5 [2] e9 }

  condition:
    any of them
}