rule TTP_XOR_MULT_DOSStub_4637 {
  strings:
    $key_4637 = { 12 5f [2] 66 47 [2] 21 45 [2] 66 54 [2] 28 58 [2] 24 52 [2] 33 59 [2] 28 17 [2] 15 }

  condition:
    any of them
}