rule TTP_XOR_MULT_DOSStub_e286 {
  strings:
    $key_e286 = { b6 ee [2] c2 f6 [2] 85 f4 [2] c2 e5 [2] 8c e9 [2] 80 e3 [2] 97 e8 [2] 8c a6 [2] b1 }

  condition:
    any of them
}