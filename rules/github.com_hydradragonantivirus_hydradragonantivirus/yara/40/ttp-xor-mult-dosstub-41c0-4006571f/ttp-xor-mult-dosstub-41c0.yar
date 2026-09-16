rule TTP_XOR_MULT_DOSStub_41c0 {
  strings:
    $key_41c0 = { 15 a8 [2] 61 b0 [2] 26 b2 [2] 61 a3 [2] 2f af [2] 23 a5 [2] 34 ae [2] 2f e0 [2] 12 }

  condition:
    any of them
}