rule TTP_XOR_MULT_DOSStub_f1c0 {
  strings:
    $key_f1c0 = { a5 a8 [2] d1 b0 [2] 96 b2 [2] d1 a3 [2] 9f af [2] 93 a5 [2] 84 ae [2] 9f e0 [2] a2 }

  condition:
    any of them
}