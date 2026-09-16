rule TTP_XOR_MULT_DOSStub_56c5 {
  strings:
    $key_56c5 = { 02 ad [2] 76 b5 [2] 31 b7 [2] 76 a6 [2] 38 aa [2] 34 a0 [2] 23 ab [2] 38 e5 [2] 05 }

  condition:
    any of them
}