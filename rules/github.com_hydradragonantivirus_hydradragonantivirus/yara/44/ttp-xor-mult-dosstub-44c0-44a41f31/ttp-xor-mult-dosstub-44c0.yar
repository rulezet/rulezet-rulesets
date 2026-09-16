rule TTP_XOR_MULT_DOSStub_44c0 {
  strings:
    $key_44c0 = { 10 a8 [2] 64 b0 [2] 23 b2 [2] 64 a3 [2] 2a af [2] 26 a5 [2] 31 ae [2] 2a e0 [2] 17 }

  condition:
    any of them
}