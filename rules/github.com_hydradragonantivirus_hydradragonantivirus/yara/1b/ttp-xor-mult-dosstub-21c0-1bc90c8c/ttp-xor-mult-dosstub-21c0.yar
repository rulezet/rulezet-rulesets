rule TTP_XOR_MULT_DOSStub_21c0 {
  strings:
    $key_21c0 = { 75 a8 [2] 01 b0 [2] 46 b2 [2] 01 a3 [2] 4f af [2] 43 a5 [2] 54 ae [2] 4f e0 [2] 72 }

  condition:
    any of them
}