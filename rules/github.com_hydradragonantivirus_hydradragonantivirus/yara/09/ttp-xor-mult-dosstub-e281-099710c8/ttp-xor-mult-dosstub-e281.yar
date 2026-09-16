rule TTP_XOR_MULT_DOSStub_e281 {
  strings:
    $key_e281 = { b6 e9 [2] c2 f1 [2] 85 f3 [2] c2 e2 [2] 8c ee [2] 80 e4 [2] 97 ef [2] 8c a1 [2] b1 }

  condition:
    any of them
}