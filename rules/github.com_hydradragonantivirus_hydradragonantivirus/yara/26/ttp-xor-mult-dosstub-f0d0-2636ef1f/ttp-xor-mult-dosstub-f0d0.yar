rule TTP_XOR_MULT_DOSStub_f0d0 {
  strings:
    $key_f0d0 = { a4 b8 [2] d0 a0 [2] 97 a2 [2] d0 b3 [2] 9e bf [2] 92 b5 [2] 85 be [2] 9e f0 [2] a3 }

  condition:
    any of them
}