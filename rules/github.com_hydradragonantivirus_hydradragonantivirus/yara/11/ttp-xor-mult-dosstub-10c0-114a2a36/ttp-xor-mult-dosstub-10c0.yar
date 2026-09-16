rule TTP_XOR_MULT_DOSStub_10c0 {
  strings:
    $key_10c0 = { 44 a8 [2] 30 b0 [2] 77 b2 [2] 30 a3 [2] 7e af [2] 72 a5 [2] 65 ae [2] 7e e0 [2] 43 }

  condition:
    any of them
}