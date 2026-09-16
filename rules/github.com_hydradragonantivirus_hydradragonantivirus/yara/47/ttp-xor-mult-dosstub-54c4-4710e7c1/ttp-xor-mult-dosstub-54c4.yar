rule TTP_XOR_MULT_DOSStub_54c4 {
  strings:
    $key_54c4 = { 00 ac [2] 74 b4 [2] 33 b6 [2] 74 a7 [2] 3a ab [2] 36 a1 [2] 21 aa [2] 3a e4 [2] 07 }

  condition:
    any of them
}