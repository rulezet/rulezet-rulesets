rule TTP_XOR_MULT_DOSStub_00c0 {
  strings:
    $key_00c0 = { 54 a8 [2] 20 b0 [2] 67 b2 [2] 20 a3 [2] 6e af [2] 62 a5 [2] 75 ae [2] 6e e0 [2] 53 }

  condition:
    any of them
}