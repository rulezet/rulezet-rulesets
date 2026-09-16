rule TTP_XOR_MULT_DOSStub_eed9 {
  strings:
    $key_eed9 = { ba b1 [2] ce a9 [2] 89 ab [2] ce ba [2] 80 b6 [2] 8c bc [2] 9b b7 [2] 80 f9 [2] bd }

  condition:
    any of them
}