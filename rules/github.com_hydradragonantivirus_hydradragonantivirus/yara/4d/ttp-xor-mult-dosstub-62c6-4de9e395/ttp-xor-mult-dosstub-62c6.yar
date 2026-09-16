rule TTP_XOR_MULT_DOSStub_62c6 {
  strings:
    $key_62c6 = { 36 ae [2] 42 b6 [2] 05 b4 [2] 42 a5 [2] 0c a9 [2] 00 a3 [2] 17 a8 [2] 0c e6 [2] 31 }

  condition:
    any of them
}