rule TTP_XOR_MULT_DOSStub_30c0 {
  strings:
    $key_30c0 = { 64 a8 [2] 10 b0 [2] 57 b2 [2] 10 a3 [2] 5e af [2] 52 a5 [2] 45 ae [2] 5e e0 [2] 63 }

  condition:
    any of them
}