rule TTP_XOR_MULT_DOSStub_44c1 {
  strings:
    $key_44c1 = { 10 a9 [2] 64 b1 [2] 23 b3 [2] 64 a2 [2] 2a ae [2] 26 a4 [2] 31 af [2] 2a e1 [2] 17 }

  condition:
    any of them
}