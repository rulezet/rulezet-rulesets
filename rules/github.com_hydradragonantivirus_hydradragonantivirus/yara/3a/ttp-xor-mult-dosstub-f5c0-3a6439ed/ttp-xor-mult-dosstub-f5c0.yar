rule TTP_XOR_MULT_DOSStub_f5c0 {
  strings:
    $key_f5c0 = { a1 a8 [2] d5 b0 [2] 92 b2 [2] d5 a3 [2] 9b af [2] 97 a5 [2] 80 ae [2] 9b e0 [2] a6 }

  condition:
    any of them
}