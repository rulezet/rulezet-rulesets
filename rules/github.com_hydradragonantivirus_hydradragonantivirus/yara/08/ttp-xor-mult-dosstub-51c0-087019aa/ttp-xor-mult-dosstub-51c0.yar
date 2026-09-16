rule TTP_XOR_MULT_DOSStub_51c0 {
  strings:
    $key_51c0 = { 05 a8 [2] 71 b0 [2] 36 b2 [2] 71 a3 [2] 3f af [2] 33 a5 [2] 24 ae [2] 3f e0 [2] 02 }

  condition:
    any of them
}