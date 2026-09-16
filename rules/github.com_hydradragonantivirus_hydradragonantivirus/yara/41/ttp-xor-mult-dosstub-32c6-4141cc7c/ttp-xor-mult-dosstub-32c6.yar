rule TTP_XOR_MULT_DOSStub_32c6 {
  strings:
    $key_32c6 = { 66 ae [2] 12 b6 [2] 55 b4 [2] 12 a5 [2] 5c a9 [2] 50 a3 [2] 47 a8 [2] 5c e6 [2] 61 }

  condition:
    any of them
}