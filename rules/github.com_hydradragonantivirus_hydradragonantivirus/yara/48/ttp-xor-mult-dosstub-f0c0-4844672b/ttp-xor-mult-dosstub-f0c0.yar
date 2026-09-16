rule TTP_XOR_MULT_DOSStub_f0c0 {
  strings:
    $key_f0c0 = { a4 a8 [2] d0 b0 [2] 97 b2 [2] d0 a3 [2] 9e af [2] 92 a5 [2] 85 ae [2] 9e e0 [2] a3 }

  condition:
    any of them
}