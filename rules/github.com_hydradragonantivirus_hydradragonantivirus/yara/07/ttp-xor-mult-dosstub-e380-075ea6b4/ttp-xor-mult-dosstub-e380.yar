rule TTP_XOR_MULT_DOSStub_e380 {
  strings:
    $key_e380 = { b7 e8 [2] c3 f0 [2] 84 f2 [2] c3 e3 [2] 8d ef [2] 81 e5 [2] 96 ee [2] 8d a0 [2] b0 }

  condition:
    any of them
}