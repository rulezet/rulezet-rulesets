rule TTP_XOR_MULT_DOSStub_f0c1 {
  strings:
    $key_f0c1 = { a4 a9 [2] d0 b1 [2] 97 b3 [2] d0 a2 [2] 9e ae [2] 92 a4 [2] 85 af [2] 9e e1 [2] a3 }

  condition:
    any of them
}